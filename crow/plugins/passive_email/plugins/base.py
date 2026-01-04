# crow/plugins/passive_email/plugins/base.py
from __future__ import annotations

import re
from typing import Iterable, List, Set
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"[a-zA-Z0-9.\-_+#~!$&',;=:]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def normalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = urlparse(d).netloc
    d = d.strip(".")
    return d


def extract_emails(text: str) -> List[str]:
    if not text:
        return []
    return EMAIL_RE.findall(text)


def unique(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        if not x:
            continue
        x = x.strip()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def filter_by_domain(emails: Iterable[str], domain: str) -> List[str]:
    d = normalize_domain(domain)
    out = []
    for e in emails:
        e = (e or "").strip()
        if e.lower().endswith("@" + d):
            out.append(e)
    return unique(out)


# مهم: محمل EmailHarvester يحاول تشغيل Plugin في كل ملف .py
# لذلك نضع Plugin فارغ حتى لا يحصل خطأ، ولا يسجل أي engine.
class Plugin:
    def __init__(self, harvester, opts):
        self.harvester = harvester
        self.opts = opts or {}
        # لا تسجل أي search method هنا
        return
