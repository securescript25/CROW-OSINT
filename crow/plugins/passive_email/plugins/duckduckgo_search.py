# crow/plugins/passive_email/plugins/duckduckgo_search.py
from __future__ import annotations

import random
import re
import time
from typing import Dict, List, Set
from urllib.parse import quote_plus, urlparse

import base
import requests


class Plugin:
    """
    Engine name: duckduckgo
    Searches DuckDuckGo for emails related to a domain.
    """

    def __init__(self, harvester, opts: Dict):
        self.harvester = harvester
        self.opts = opts or {}
        # تسجيل الخيارات عند التهيئة
        logger.info(
            f"DuckDuckGo plugin initialized with opts: {list(self.opts.keys())}"
        )
        self.harvester.register_plugin("duckduckgo", {"search": self.search})

    def search(self, domain: str, limit: int = 100) -> List[str]:
        """البحث في DuckDuckGo لإيميلات متعلقة بالنطاق"""
        # تسجيل بدء البحث بوضوح
        logger.info(f"🚀 DUCKDUCKGO SEARCH STARTING for domain: {domain}")
        logger.info(f"DuckDuckGo proxy setting: {self.opts.get('proxy', 'No proxy')}")

        domain = base.normalize_domain(domain)

        max_pages = int(self.opts.get("ddg_pages", 2))
        base_delay = float(self.opts.get("ddg_delay", 2.0))
        max_results = min(limit, max_pages * 30)

        user_agent = self._get_user_agent()
        proxy = self._get_proxy()

        queries = self._generate_queries(domain)

        all_emails: Set[str] = set()
        session = requests.Session()

        logger.info(f"DuckDuckGo: Using {len(queries)} queries, {max_pages} pages each")
        logger.info(f"DuckDuckGo queries: {queries}")

        for query_idx, query in enumerate(queries):
            if len(all_emails) >= max_results:
                break

            logger.info(
                f"DuckDuckGo processing query {query_idx + 1}/{len(queries)}: '{query}'"
            )

            for page in range(max_pages):
                if len(all_emails) >= max_results:
                    break

                try:
                    logger.info(
                        f"DuckDuckGo search: '{query}' - Page {page + 1}/{max_pages}"
                    )
                    emails = self._search_ddg_page(
                        session=session,
                        query=query,
                        page=page,
                        user_agent=user_agent,
                        proxy=proxy,
                    )

                    new_emails = [e for e in emails if e not in all_emails]
                    if new_emails:
                        logger.info(
                            f"DuckDuckGo: Found {len(new_emails)} new emails from query '{query}'"
                        )
                        for email in new_emails[:3]:  # تسجيل أول 3 إيميلات فقط
                            logger.debug(f"DuckDuckGo email found: {email}")

                    all_emails.update(emails)

                    # تأخير ذكي بين الطلبات
                    delay = random.uniform(base_delay, base_delay + 1.5)
                    logger.debug(f"DuckDuckGo: Sleeping for {delay:.1f} seconds")
                    time.sleep(delay)

                except Exception as e:
                    logger.error(
                        f"DuckDuckGo search error for query '{query}': {str(e)}"
                    )
                    logger.exception("DuckDuckGo error details:")
                    continue

        # تصفية النتائج
        filtered = base.filter_by_domain(list(all_emails), domain)

        logger.info(
            f"✅ DUCKDUCKGO SEARCH COMPLETED. Found {len(filtered)} emails for {domain}"
        )
        if filtered:
            logger.info(f"DuckDuckGo emails found: {filtered[:5]}")  # أول 5 إيميلات فقط

        return filtered[:limit]

    def _generate_queries(self, domain: str) -> List[str]:
        """إنشاء استعلامات بحث لـ DuckDuckGo"""
        queries = [
            f'site:{domain} "@{domain}"',
            f'site:{domain} "email"',
            f'site:{domain} "contact"',
            f'"{domain}" "@gmail.com"',
            f'"{domain}" "@yahoo.com"',
            f'"{domain}" "@hotmail.com"',
            f'"{domain}" "@outlook.com"',
        ]

        # تقليل الاستعلامات إذا كان النطاق .ye (مشاكل محتملة)
        if domain.endswith(".ye"):
            logger.warning(f"Domain {domain} ends with .ye - using limited queries")
            queries = queries[:3]  # فقط أول 3 استعلامات

        return queries

    def _search_ddg_page(
        self, session, query: str, page: int, user_agent: str, proxy: str = None
    ) -> List[str]:
        """البحث في صفحة محددة من DuckDuckGo"""
        s = page * 30
        encoded_query = quote_plus(query)

        # ✅ **تم إصلاح الرابط هنا** - استخدام النطاق الصحيح
        url = f"https://duckduckgo.com/html/?q={encoded_query}&s={s}"

        headers = self._create_headers(user_agent)
        proxies = self._create_proxies(proxy)

        logger.info(f"DuckDuckGo requesting: {url}")
        logger.debug(f"DuckDuckGo headers: {headers}")

        try:
            # ⚠️ ملاحظة: DuckDuckGo يتوقع GET وليس POST
            response = session.get(
                url, headers=headers, proxies=proxies, timeout=15, allow_redirects=True
            )

            logger.info(f"DuckDuckGo response status: {response.status_code}")

            if response.status_code == 200:
                emails = base.extract_emails(response.text)
                logger.debug(f"DuckDuckGo raw emails found: {len(emails)}")

                # تنظيف النتائج
                cleaned_emails = []
                for email in emails:
                    email = email.strip().lower()
                    if self._is_valid_email(email):
                        cleaned_emails.append(email)

                logger.info(
                    f"✅ DuckDuckGo found {len(cleaned_emails)} valid emails on page {page}"
                )
                return cleaned_emails
            else:
                logger.warning(
                    f"⚠️ DuckDuckGo: HTTP {response.status_code} for query: {query}"
                )

        except requests.exceptions.Timeout:
            logger.warning("⏰ DuckDuckGo: Timeout for query: {query}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"🔌 DuckDuckGo connection error: {str(e)}")
        except Exception as e:
            logger.error(f"❌ DuckDuckGo request error: {str(e)}")
            logger.exception("DuckDuckGo exception details:")

        return []

    def _create_headers(self, user_agent: str) -> Dict[str, str]:
        """إنشاء headers لـ DuckDuckGo"""
        return {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
        }

    def _create_proxies(self, proxy):
        """إنشاء proxies dictionary"""
        if not proxy:
            logger.debug("DuckDuckGo: No proxy configured")
            return None

        try:
            if isinstance(proxy, str):
                parsed = urlparse(proxy)
            else:
                parsed = proxy

            if parsed.scheme and parsed.netloc:
                scheme = parsed.scheme
                proxy_url = f"{scheme}://{parsed.netloc}"
                logger.info(f"DuckDuckGo using proxy: {proxy_url}")
                return {"http": proxy_url, "https": proxy_url}
        except Exception as e:
            logger.error(f"Error parsing proxy: {str(e)}")

        return None

    def _get_user_agent(self) -> str:
        """الحصول على User-Agent"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]

        ua = self.opts.get("useragent") or self.opts.get("userAgent")
        selected_ua = ua or random.choice(user_agents)
        logger.debug(f"DuckDuckGo User-Agent: {selected_ua[:50]}...")
        return selected_ua

    def _get_proxy(self):
        """معالجة الـ proxy"""
        proxy = self.opts.get("proxy")
        if not proxy:
            logger.debug("DuckDuckGo: No proxy configured")
            return None

        if hasattr(proxy, "scheme") and hasattr(proxy, "netloc"):
            logger.debug(f"DuckDuckGo: Using proxy {proxy.scheme}://{proxy.netloc}")
            return proxy

        if isinstance(proxy, str):
            try:
                parsed = urlparse(proxy)
                logger.debug(
                    f"DuckDuckGo: Parsed proxy string: {parsed.scheme}://{parsed.netloc}"
                )
                return parsed
            except Exception as e:
                logger.error(f"DuckDuckGo: Error parsing proxy string: {str(e)}")
                return None

        return None

    def _is_valid_email(self, email: str) -> bool:
        """التحقق من صحة الإيميل"""
        if not email or "@" not in email:
            return False

        # تجاهل نطاقات البريد الوهمي
        disposable_domains = {
            "mailinator.com",
            "guerrillamail.com",
            "10minutemail.com",
            "tempmail.com",
            "yopmail.com",
            "trashmail.com",
            "temp-mail.org",
            "fakeinbox.com",
            "getairmail.com",
        }

        domain = email.split("@")[-1].lower()
        if domain in disposable_domains:
            return False

        # تجاهل الإيميلات التي تحتوي على رموز غير عادية
        if "..." in email or ".." in email:
            return False

        # تحقق من صيغة الإيميل الأساسية
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(email_regex, email))


# تسجيل الـ logger - تأكد من أن هذا موجود في نهاية الملف
try:
    from crow.core.logger import logger
except ImportError:
    import logging

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    # إضافة handler إذا لم يكن موجوداً
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
