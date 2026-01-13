from __future__ import annotations

from typing import Any, Dict, List
import importlib.util
import os
import traceback

from crow.core.bases import PassivePlugin
from crow.core.logger import logger as default_logger
from crow.core.models import PluginOutput


def _clean(t: str) -> str:
    return (t or "").strip().lower()


def _domain_only(target: str) -> str:
    t = _clean(target)
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    return t.replace("www.", "")


def _brand_from_domain(domain: str) -> str:
    return domain.split(".", 1)[0] if "." in domain else domain


def _safe_load_class(py_file: str, class_name: str):
    py_file = os.path.abspath(py_file)
    if not os.path.exists(py_file):
        raise FileNotFoundError(py_file)

    mod_name = f"_crow_social_{os.path.basename(py_file).replace('.py','')}"
    spec = importlib.util.spec_from_file_location(mod_name, py_file)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create spec for {py_file}")

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)  # type: ignore
    except Exception as e:
        tb = traceback.format_exc()
        raise ImportError(f"Error executing {py_file}:\n{tb}") from e

    if not hasattr(module, class_name):
        raise ImportError(f"{class_name} not found in {py_file}")
    return getattr(module, class_name)


class PassiveSocialPlugin(PassivePlugin):
    name = "social"
    description = "Social harvesting: site_extract + optional bing + guess (with debug)"
    version = "STABLE-8.0"

    def __init__(self, config=None, logger_obj=None):
        self.config = config or {}
        self.logger = logger_obj or default_logger

    def run(self, target: str, **kwargs) -> PluginOutput:
        output = PluginOutput(plugin=self.name)

        if not target or not target.strip():
            output.errors.append("Empty target")
            return output

        domain = _domain_only(target)
        brand = _brand_from_domain(domain)

        here = os.path.dirname(os.path.abspath(__file__))
        engines_dir = os.path.join(here, "plugins")

        engines = []
        load_errors: List[str] = []

        # 1) site_extract
        try:
            cls = _safe_load_class(os.path.join(engines_dir, "site_extract_module.py"), "SiteExtractModule")
            engines.append(cls(self.config, self.logger))
        except Exception as e:
            load_errors.append(f"Failed to load SiteExtractModule: {e}")

        # 2) bing_search (optional)
        bing_path = os.path.join(engines_dir, "search_bing_module.py")
        if os.path.exists(bing_path):
            try:
                cls = _safe_load_class(bing_path, "BingHtmlSearchModule")
                engines.append(cls(self.config, self.logger))
            except Exception as e:
                load_errors.append(f"Failed to load BingHtmlSearchModule: {e}")

        # 3) guess engine (always, returns multi-platform candidates)
        try:
            cls = _safe_load_class(os.path.join(engines_dir, "guess_module.py"), "GuessModule")
            engines.append(cls(self.config, self.logger))
        except Exception as e:
            load_errors.append(f"Failed to load GuessModule: {e}")

        # Attach load errors (debug)
        if load_errors:
            output.errors.extend(load_errors)

        if not engines:
            output.errors.append("No social engine modules loaded.")
            output.errors.append(f"plugin_file={__file__}")
            return output

        # Debug: show loaded engines
        output.errors.append(f"DEBUG: engines_loaded={[getattr(e,'name',e.__class__.__name__) for e in engines]}")

        rows: List[Dict[str, Any]] = []
        for eng in engines:
            eng_name = getattr(eng, "name", eng.__class__.__name__)
            try:
                output.errors.append(f"DEBUG: running_engine={eng_name} domain={domain} brand={brand}")
                res = eng.collect(domain=domain, brand=brand)
                output.errors.append(f"DEBUG: engine={eng_name} returned={len(res or [])}")

                for r in res or []:
                    if not r.get("platform") or not r.get("url"):
                        continue
                    rows.append({
                        "plugin": self.name,
                        "type": "SOCIAL",
                        "engine": eng_name,
                        "platform": r.get("platform"),
                        "url": r.get("url"),
                        "username": r.get("username"),
                        "exists": True,
                        "status_code": r.get("status_code", 200),
                        "response_time": r.get("response_time", 0),
                        "source": r.get("source"),
                    })
            except Exception as e:
                output.errors.append(f"Engine {eng_name} failed: {e}")

        # Dedup
        seen = set()
        out = []
        for r in rows:
            key = (str(r.get("platform")).lower(), r.get("url"))
            if key in seen:
                continue
            seen.add(key)
            out.append(r)

        output.results = out

        # If nothing, keep an explicit message
        if not output.results:
            output.errors.append("No social links found.")

        return output


Plugin = PassiveSocialPlugin
__all__ = ["PassiveSocialPlugin", "Plugin"]
