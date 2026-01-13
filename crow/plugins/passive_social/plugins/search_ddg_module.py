import re
import time
from typing import Any, Dict, List
from urllib.parse import unquote

import requests

UDDG_RE = re.compile(r"uddg=([^&]+)")

PLATFORM_RULES = [
    ("Twitter", re.compile(r"https?://(www\.)?(twitter\.com|x\.com)/[A-Za-z0-9_]{1,30}", re.I)),
    ("Instagram", re.compile(r"https?://(www\.)?instagram\.com/[A-Za-z0-9_.]{1,30}", re.I)),
    ("LinkedIn", re.compile(r"https?://(www\.)?linkedin\.com/(company|in)/[A-Za-z0-9\-_%/]+", re.I)),
    ("GitHub", re.compile(r"https?://(www\.)?github\.com/[A-Za-z0-9_.-]{1,39}", re.I)),
    ("Facebook", re.compile(r"https?://(www\.)?facebook\.com/[A-Za-z0-9.\-_/]+", re.I)),
    ("YouTube", re.compile(r"https?://(www\.)?(youtube\.com|youtu\.be)/[A-Za-z0-9\-_%/?=&]+", re.I)),
    ("Telegram", re.compile(r"https?://(t\.me)/[A-Za-z0-9_]{3,}", re.I)),
    ("TikTok", re.compile(r"https?://(www\.)?tiktok\.com/@[A-Za-z0-9_.]{2,24}", re.I)),
]


class DuckDuckGoSearchModule:
    name = "ddg_search"

    def __init__(self, config, logger):
        self.config = config or {}
        self.logger = logger
        self.timeout = int(self.config.get("timeout", 20))
        self.pages = int(self.config.get("search_pages", 4))
        self.pause = float(self.config.get("search_pause", 1.1))

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CROW-OSINT/5.2",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def _ddg_html(self, query: str, start: int = 0) -> str:
        url = "https://duckduckgo.com/html/"
        r = self.session.post(url, data={"q": query, "s": str(start)}, timeout=self.timeout)
        r.raise_for_status()
        return r.text or ""

    def _extract_urls(self, html: str) -> List[str]:
        hrefs = re.findall(r'href="([^"]+)"', html or "")
        out = []
        for h in hrefs:
            if "duckduckgo.com/l/" in h and "uddg=" in h:
                m = UDDG_RE.search(h)
                if m:
                    out.append(unquote(m.group(1)))
            elif h.startswith("http"):
                out.append(h)
        # dedup
        out = list(dict.fromkeys(out))
        return out

    def collect(self, domain: str, brand: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        tokens = [t for t in [brand, domain] if t]
        if not tokens:
            return results

        token_expr = f"({tokens[0]})" if len(tokens) == 1 else f"({tokens[0]} OR {tokens[1]})"

        queries = [
            f'site:linkedin.com/company {token_expr}',
            f'site:linkedin.com/in {token_expr}',
            f'site:twitter.com {token_expr}',
            f'site:x.com {token_expr}',
            f'site:instagram.com {token_expr}',
            f'site:facebook.com {token_expr}',
            f'site:youtube.com {token_expr}',
            f'site:github.com {token_expr}',
            f'site:t.me {token_expr}',
            f'site:tiktok.com {token_expr}',
        ]

        for q in queries:
            start = 0
            for _ in range(self.pages):
                try:
                    html = self._ddg_html(q, start=start)
                    urls = self._extract_urls(html)
                    for u in urls:
                        for platform, pat in PLATFORM_RULES:
                            mm = pat.search(u)
                            if mm:
                                results.append({"platform": platform, "url": mm.group(0), "source": "ddg"})
                    start += 50
                    time.sleep(self.pause)
                except Exception as e:
                    self.logger.error(f"[ddg_search] failed: query={q} err={e}")
                    break

        return results
