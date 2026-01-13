import re
from typing import Any, Dict, List, Optional

import requests

HREF_RE = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)

SOCIAL_PATTERNS = [
    ("Twitter", re.compile(r"https?://(www\.)?(twitter\.com|x\.com)/[A-Za-z0-9_]{1,30}", re.I)),
    ("Instagram", re.compile(r"https?://(www\.)?instagram\.com/[A-Za-z0-9_.]{1,30}", re.I)),
    ("LinkedIn", re.compile(r"https?://(www\.)?linkedin\.com/(company|in)/[A-Za-z0-9\-_%/]+", re.I)),
    ("GitHub", re.compile(r"https?://(www\.)?github\.com/[A-Za-z0-9_.-]{1,39}", re.I)),
    ("Facebook", re.compile(r"https?://(www\.)?facebook\.com/[A-Za-z0-9.\-_/]+", re.I)),
    ("YouTube", re.compile(r"https?://(www\.)?(youtube\.com|youtu\.be)/[A-Za-z0-9\-_%/?=&]+", re.I)),
    ("Telegram", re.compile(r"https?://(t\.me)/[A-Za-z0-9_]{3,}", re.I)),
    ("TikTok", re.compile(r"https?://(www\.)?tiktok\.com/@[A-Za-z0-9_.]{2,24}", re.I)),
    ("Discord", re.compile(r"https?://(discord\.gg|discord\.com/invite)/[A-Za-z0-9]+", re.I)),
]

COMMON_PATHS = ["/", "/about", "/contact", "/support", "/company", "/press"]


class SiteExtractModule:
    name = "site_extract"

    def __init__(self, config, logger):
        self.config = config or {}
        self.logger = logger
        self.timeout = int(self.config.get("timeout", 20))
        self.max_pages = int(self.config.get("site_extract_pages", 4))

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CROW-OSINT/4.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def _fetch(self, url: str) -> Optional[str]:
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if 200 <= r.status_code < 400 and r.text:
                return r.text
        except Exception:
            return None
        return None

    def collect(self, domain: str, brand: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not domain:
            return results

        urls = []
        for base in (f"https://{domain}", f"http://{domain}"):
            for p in COMMON_PATHS:
                urls.append(base + p)

        urls = urls[: self.max_pages]

        for url in urls:
            html = self._fetch(url)
            if not html:
                continue

            for m in HREF_RE.finditer(html):
                href = (m.group(1) or "").strip()
                if not href.startswith("http"):
                    continue

                for platform, pat in SOCIAL_PATTERNS:
                    mm = pat.search(href)
                    if mm:
                        results.append({"platform": platform, "url": mm.group(0), "source": "site"})
        return results
