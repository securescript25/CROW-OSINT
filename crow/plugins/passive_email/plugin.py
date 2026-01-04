# crow/plugins/passive_email/plugin.py
# Integrated EmailHarvester (library-style) as a CROW passive plugin
# (Removed: termcolor / colored output section بالكامل)

from __future__ import annotations

import os
import re
import sys
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

try:
    import validators  # type: ignore
except Exception:
    validators = None  # fallback


from crow.core.bases import PassivePlugin
from crow.core.logger import logger
from crow.core.models import PluginOutput

# -----------------------------
# EmailHarvester core (adapted)
# -----------------------------


class MyParser:
    def __init__(self) -> None:
        self.temp: List[str] = []
        self.results: str = ""
        self.word: str = ""

    def extract(self, results: str, word: str) -> None:
        self.results = results or ""
        self.word = word or ""

    def genericClean(self) -> None:
        for e in """<KW> </KW> </a> <b> </b> </div> <em> </em> <p> </span>
                    <strong> </strong> <title> <wbr> </wbr>""".split():
            self.results = self.results.replace(e, "")
        for e in "%2f %3a %3A %3C %3D & / : ; < = > \\".split():
            self.results = self.results.replace(e, " ")

    def emails(self) -> List[str]:
        self.genericClean()
        reg_emails = re.compile(
            r"[a-zA-Z0-9.\-_+#~!$&\',;=:]+"
            r"@"
            r"[a-zA-Z0-9.-]*" + re.escape(self.word)
        )
        self.temp = reg_emails.findall(self.results)
        return self.unique()

    def unique(self) -> List[str]:
        return list(set(self.temp))


def unique_list(data: List[str]) -> List[str]:
    return list(set(data))


def check_proxy_url(url: str):
    url_checked = urlparse(url)
    if (url_checked.scheme not in ("http", "https")) or (url_checked.netloc == ""):
        raise ValueError(f"Invalid Proxy URL: {url} (example: http://127.0.0.1:8080).")
    return url_checked


def check_domain(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("Domain is empty.")

    if validators is not None:
        ok = validators.domain(value)
        if ok:
            return value
        raise ValueError(f"Invalid domain: {value}")

    # Fallback regex if validators lib not present
    if re.fullmatch(r"(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}", value):
        return value
    raise ValueError(f"Invalid domain: {value}")


class EmailHarvester:
    """
    Loads search-engine plugins from ./plugins (next to this file),
    and runs them to harvest emails for a domain.
    """

    def __init__(
        self, user_agent: str, proxy: Optional[str] = None, timeout: float = 10.0
    ):
        self.plugins: Dict[str, Dict[str, Any]] = {}
        self.proxy = proxy
        self.userAgent = user_agent
        self.timeout = timeout
        self.parser = MyParser()
        self.activeEngine = "None"

        base_dir = os.path.dirname(os.path.abspath(__file__))
        plugins_path = os.path.join(
            base_dir, "plugins"
        )  # expect: crow/plugins/passive_email/plugins/

        if not os.path.isdir(plugins_path):
            # Not fatal, but nothing will work without engines
            logger.warning(f"[passive_email] plugins dir not found: {plugins_path}")
            return

        sys.path.insert(0, plugins_path)

        for f in os.listdir(plugins_path):
            fname, ext = os.path.splitext(f)
            if ext != ".py" or fname.startswith("_"):
                continue
            try:
                mod = __import__(fname, fromlist=[""])
                # Plugin convention: class Plugin(self, opts) and it will call register_plugin()
                _ = mod.Plugin(
                    self, {"useragent": user_agent, "proxy": proxy, "timeout": timeout}
                )
            except Exception as e:
                logger.error(
                    f"[passive_email] failed loading engine plugin '{fname}': {e}"
                )

    def register_plugin(self, search_method: str, functions: Dict[str, Any]) -> None:
        self.plugins[search_method] = functions

    def get_plugins(self) -> Dict[str, Dict[str, Any]]:
        return self.plugins

    # --- helpers for engine plugins ---
    def init_search(
        self,
        url: str,
        word: str,
        limit: int,
        counterInit: int,
        counterStep: int,
        engineName: str,
    ) -> None:
        self.results = ""
        self.totalresults = ""
        self.limit = int(limit)
        self.counter = int(counterInit)
        self.url = url
        self.step = int(counterStep)
        self.word = word
        self.activeEngine = engineName

    def do_search(self) -> None:
        urly = self.url.format(counter=str(self.counter), word=self.word)
        headers = {"User-Agent": self.userAgent}

        proxies = None
        if self.proxy:
            pu = check_proxy_url(self.proxy)
            proxies = {pu.scheme: f"http://{pu.netloc}"}

        r = requests.get(urly, headers=headers, proxies=proxies, timeout=self.timeout)

        if r.encoding is None:
            r.encoding = "UTF-8"

        self.results = r.content.decode(r.encoding, errors="ignore")
        self.totalresults += self.results

    def process(self) -> None:
        while self.counter < self.limit:
            self.do_search()
            time.sleep(1)
            self.counter += self.step

    def get_emails(self) -> List[str]:
        self.parser.extract(self.totalresults, self.word)
        return self.parser.emails()


# -----------------------------
# CROW Passive Plugin wrapper
# -----------------------------


class PassiveEmailPlugin(PassivePlugin):
    name = "email"
    description = "Harvest emails from search engines (EmailHarvester engines via passive_email/plugins/)"

    def run(self, target: str, **kwargs) -> PluginOutput:
        """
        kwargs supported:
          - engine: "all" (default) or single engine name
          - limit: int (default 100)
          - user_agent: str
          - proxy: str (e.g., http://127.0.0.1:8080)
          - exclude: "google,twitter" (only when engine=all)
          - timeout: float seconds (requests timeout)
        """
        output = PluginOutput(plugin=self.name)

        try:
            domain = check_domain(target)
        except Exception as e:
            output.errors.append(f"Invalid domain: {e}")
            return output

        engine = str(kwargs.get("engine", "all")).strip().lower()
        limit = int(kwargs.get("limit", 100))
        exclude_raw = str(kwargs.get("exclude", "")).strip()
        excluded = (
            [x.strip().lower() for x in exclude_raw.split(",") if x.strip()]
            if exclude_raw
            else []
        )

        user_agent = str(
            kwargs.get(
                "user_agent",
                "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
            )
        )
        proxy = kwargs.get("proxy", None)
        timeout = float(kwargs.get("timeout", 10.0))

        logger.info(
            f"Running EmailHarvester on {domain} (engine={engine}, limit={limit})"
        )

        harvester = EmailHarvester(user_agent=user_agent, proxy=proxy, timeout=timeout)
        plugins = harvester.get_plugins()

        if not plugins:
            output.errors.append(
                "No EmailHarvester engine plugins loaded. Create: crow/plugins/passive_email/plugins/*.py"
            )
            return output

        all_emails: List[str] = []

        try:
            if engine == "all":
                for search_engine, funcs in plugins.items():
                    if search_engine.lower() in excluded:
                        continue
                    if "search" not in funcs:
                        continue
                    try:
                        all_emails += funcs["search"](domain, limit)
                    except Exception as e:
                        msg = f"engine '{search_engine}' failed: {e}"
                        logger.error(msg)
                        output.errors.append(msg)
            else:
                if engine not in plugins:
                    output.errors.append(f"Search engine plugin not found: {engine}")
                    return output
                funcs = plugins[engine]
                if "search" not in funcs:
                    output.errors.append(f"Engine '{engine}' does not expose search()")
                    return output
                all_emails = funcs["search"](domain, limit)

        except Exception as e:
            output.errors.append(str(e))
            return output

        all_emails = unique_list([e for e in all_emails if e])

        if not all_emails:
            return output

        # store results
        for email in all_emails:
            output.results.append(
                {
                    "plugin": self.name,
                    "type": "EMAIL",
                    "domain": domain,
                    "email": email,
                }
            )

        return output
