# crow/plugins/passive_email/plugins/site_crawl.py
from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import base  # <-- مهم: ليس from .base
import requests


class Plugin:
    """
    Engine name: site
    Crawls a few pages within the same domain and extracts emails ending with @domain.
    """

    def __init__(self, harvester, opts: Dict):
        self.harvester = harvester
        self.opts = opts or {}
        self.harvester.register_plugin("site", {"search": self.search})

    def _proxies(self):
        proxy = self.opts.get("proxy")
        if not proxy:
            return None
        # proxy قد يكون urlparse result أو string
        if hasattr(proxy, "scheme") and hasattr(proxy, "netloc"):
            return {proxy.scheme: f"{proxy.scheme}://{proxy.netloc}"}
        if isinstance(proxy, str):
            u = urlparse(proxy)
            if u.scheme and u.netloc:
                return {u.scheme: f"{u.scheme}://{u.netloc}"}
        return None

    def _headers(self):
        ua = self.opts.get("useragent") or self.opts.get("userAgent")
        if not ua:
            ua = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"
        return {"User-Agent": ua}

    def search(self, domain: str, limit: int = 100) -> List[str]:
        domain = base.normalize_domain(domain)

        max_pages = int(self.opts.get("max_pages", 15))
        timeout = float(self.opts.get("timeout", 6.0))

        start_urls = [
            f"https://{domain}/",
            f"https://www.{domain}/",
            f"http://{domain}/",
            f"http://www.{domain}/",
        ]

        q = deque(start_urls)
        visited: Set[str] = set()
        emails: List[str] = []

        sess = requests.Session()
        proxies = self._proxies()
        headers = self._headers()

        def same_site(u: str) -> bool:
            try:
                p = urlparse(u)
                host = (p.netloc or "").lower().strip(".")
                return host == domain or host == f"www.{domain}"
            except Exception:
                return False

        while q and len(visited) < max_pages and len(emails) < limit:
            url = q.popleft()
            if url in visited:
                continue
            visited.add(url)

            try:
                r = sess.get(
                    url,
                    headers=headers,
                    proxies=proxies,
                    timeout=timeout,
                    allow_redirects=True,
                )
                if r.status_code >= 400:
                    continue

                ctype = (r.headers.get("Content-Type") or "").lower()
                if "text/html" not in ctype:
                    continue

                html = r.text or ""
                emails.extend(base.extract_emails(html))
                emails = base.unique(emails)

                # استخراج روابط داخلية بسيطة
                for href in set(re.findall(r'href=["\'](.*?)["\']', html, flags=re.I)):
                    if not href:
                        continue
                    if href.startswith("mailto:"):
                        continue
                    nxt = urljoin(r.url, href)

                    if any(
                        nxt.lower().endswith(ext)
                        for ext in [".jpg", ".png", ".pdf", ".zip", ".exe", ".mp4"]
                    ):
                        continue

                    if (
                        same_site(nxt)
                        and nxt not in visited
                        and len(visited) < max_pages
                    ):
                        q.append(nxt)

            except Exception:
                continue

        emails = base.filter_by_domain(emails, domain)
        return emails[:limit]
