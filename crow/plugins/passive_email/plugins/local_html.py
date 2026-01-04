# crow/plugins/passive_email/plugins/local_html.py
from __future__ import annotations

from typing import Dict, List

import base  # <-- مهم


class Plugin:
    """
    Engine name: local_html
    Reads a local HTML file and extracts emails ending with @domain.
    opts['html_path'] required.
    """

    def __init__(self, harvester, opts: Dict):
        self.harvester = harvester
        self.opts = opts or {}
        self.harvester.register_plugin("local_html", {"search": self.search})

    def search(self, domain: str, limit: int = 100) -> List[str]:
        domain = base.normalize_domain(domain)
        html_path = self.opts.get("html_path")
        if not html_path:
            return []

        try:
            with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
        except Exception:
            return []

        emails = base.unique(base.extract_emails(data))
        emails = base.filter_by_domain(emails, domain)
        return emails[:limit]
