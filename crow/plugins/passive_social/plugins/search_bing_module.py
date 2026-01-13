import re
import time
from typing import Any, Dict, List
from urllib.parse import quote_plus

import requests

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

class BingHtmlSearchModule:
    name = "bing_search"

    def __init__(self, config, logger):
        self.config = config or {}
        self.logger = logger
        self.timeout = int(self.config.get("timeout", 20))
        self.pages = int(self.config.get("bing_pages", 3))
        self.pause = float(self.config.get("bing_pause", 1.0))

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

    def _bing_html(self, query: str, first: int = 1) -> str:
        url = f"https://www.bing.com/search?q={quote_plus(query)}&first={first}"
        r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        r.raise_for_status()
        return r.text or ""

    def _extract_urls(self, html: str) -> List[str]:
        # استخراج روابط عامة من HTML
        urls = re.findall(r'href="(https?://[^"]+)"', html or "")
        # تقليل الضوضاء
        out = []
        for u in urls:
            if "bing.com" in u:
                continue
            out.append(u)
        # dedup
        return list(dict.fromkeys(out))

    def collect(self, domain: str, brand: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        tokens = [t for t in [brand, domain] if t]
        if not tokens:
            return results

        token_expr = f'("{tokens[0]}") OR ("{tokens[1]}")' if len(tokens) > 1 else f'"{tokens[0]}"'

        queries = [
            f"site:linkedin.com/company {token_expr}",
            f"site:linkedin.com/in {token_expr}",
            f"site:twitter.com {token_expr}",
            f"site:x.com {token_expr}",
            f"site:instagram.com {token_expr}",
            f"site:facebook.com {token_expr}",
            f"site:youtube.com {token_expr}",
            f"site:github.com {token_expr}",
            f"site:t.me {token_expr}",
            f"site:tiktok.com {token_expr}",
        ]

        for q in queries:
            first = 1
            for _ in range(self.pages):
                try:
                    html = self._bing_html(q, first=first)
                    urls = self._extract_urls(html)

                    for u in urls:
                        for platform, pat in PLATFORM_RULES:
                            mm = pat.search(u)
                            if mm:
                                results.append({"platform": platform, "url": mm.group(0), "source": "bing"})
                    first += 10
                    time.sleep(self.pause)
                except Exception as e:
                    self.logger.error(f"[bing_search] failed: query={q} err={e}")
                    break

        return results
