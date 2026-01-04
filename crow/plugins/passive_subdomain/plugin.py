"""Passive Subdomain Finder – CT-Logs + small brute-force (CROW Plugin)."""

from typing import Any, Dict, List, Set

import dns.resolver
import requests

from crow.core.bases import PassivePlugin
from crow.core.models import BaseRecord, PluginOutput


class PassiveSubdomainPlugin(PassivePlugin):
    name = "subdomain"
    description = (
        "Subdomain discovery using CT-Logs (crt.sh) + small brute-force wordlist"
    )

    def run(self, target: str, **kwargs) -> PluginOutput:
        config: Dict[str, Any] = kwargs.get("config", {}) or {}
        log = kwargs.get("logger", None)

        timeout = int(config.get("timeout", 10))
        ua = config.get("user_agent", "CROW-OSINT/0.1.0")

        if log:
            log.info(f"[subdomain] Running on target: {target}")

        output = PluginOutput(plugin=self.name)

        try:
            # 1) Collect candidate subdomains
            candidates: Set[str] = set()

            ct_subdomains = self._ct_logs(target, timeout=timeout, user_agent=ua)
            candidates.update(ct_subdomains)

            brute_subdomains = self._brute_force(target)
            candidates.update(brute_subdomains)

            # 2) Resolve candidates (A records)
            for subdomain in sorted(candidates):
                try:
                    answers = dns.resolver.resolve(subdomain, "A")
                    record = BaseRecord(
                        plugin=self.name,
                        domain=subdomain,
                        type="A",
                        values=[str(r) for r in answers],
                    )
                    output.results.append(record)

                except dns.resolver.NXDOMAIN:
                    # No A record
                    continue
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.Timeout:
                    # Optional: collect as error if you want
                    # output.errors.append(f"DNS timeout: {subdomain}")
                    continue
                except Exception:
                    continue

        except Exception as e:
            if log:
                log.error(f"[subdomain] Error: {e}")
            output.errors.append(str(e))

        return output

    def _ct_logs(
        self, domain: str, timeout: int = 10, user_agent: str = "CROW-OSINT/0.1.0"
    ) -> List[str]:
        """
        Extract subdomains from Certificate Transparency logs via crt.sh.

        Returns a list of subdomains like: api.example.com, mail.example.com ...
        """
        try:
            # crt.sh expects %.domain ; %25 is URL-encoded '%'
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            headers = {"User-Agent": user_agent}

            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()

            text = (resp.text or "").strip()
            if not text:
                return []

            data = resp.json()
            found: Set[str] = set()

            for entry in data if isinstance(data, list) else []:
                nv = str(entry.get("name_value", "")).strip()
                if not nv:
                    continue

                # crt.sh may return multiple names separated by newlines
                for host in nv.splitlines():
                    host = host.strip().lower()

                    # remove wildcard prefix
                    if host.startswith("*."):
                        host = host[2:]

                    # filter by domain suffix
                    if (
                        host.endswith(f".{domain}")
                        and host != domain
                        and "*" not in host
                        and "@" not in host
                    ):
                        found.add(host)

            return sorted(found)
        except Exception:
            return []

    def _brute_force(self, domain: str) -> List[str]:
        """
        Very small brute-force using a built-in wordlist.
        Resolves A record to validate existence.
        """
        wordlist = [
            "www",
            "mail",
            "ftp",
            "admin",
            "blog",
            "shop",
            "api",
            "dev",
            "test",
            "staging",
        ]
        found: List[str] = []

        for word in wordlist:
            sub = f"{word}.{domain}"
            try:
                dns.resolver.resolve(sub, "A")
                found.append(sub)
            except dns.resolver.NXDOMAIN:
                continue
            except dns.resolver.NoAnswer:
                continue
            except Exception:
                continue

        return found
