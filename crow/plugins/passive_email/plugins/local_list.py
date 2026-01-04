# crow/plugins/passive_email/plugins/local_list.py
from __future__ import annotations

from typing import Dict, List

import base  # <-- مهم


class Plugin:
    """
    Engine name: local_list
    Reads emails from a local text file then filters @domain.
    opts['list_path'] required.
    """

    def __init__(self, harvester, opts: Dict):
        self.harvester = harvester
        self.opts = opts or {}
        self.harvester.register_plugin("local_list", {"search": self.search})

    def search(self, domain: str, limit: int = 100) -> List[str]:
        domain = base.normalize_domain(domain)
        list_path = self.opts.get("list_path")
        if not list_path:
            return []

        try:
            with open(list_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [x.strip() for x in f.readlines()]
        except Exception:
            return []

        emails = base.unique([x for x in lines if "@" in x])
        emails = base.filter_by_domain(emails, domain)
        return emails[:limit]
