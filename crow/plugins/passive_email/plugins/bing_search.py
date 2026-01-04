# crow/plugins/passive_email/plugins/bing_search.py
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
    Engine name: bing
    Searches Bing for emails related to a domain.
    Opts supported:
      - bing_pages: number of pages to scrape (default: 2)
      - bing_delay: delay between requests in seconds (default: 3-5)
    """

    def __init__(self, harvester, opts: Dict):
        self.harvester = harvester
        self.opts = opts or {}
        # تسجيل الخيارات عند التهيئة
        logger.info(f"Bing plugin initialized with opts: {list(self.opts.keys())}")
        self.harvester.register_plugin("bing", {"search": self.search})

    def search(self, domain: str, limit: int = 100) -> List[str]:
        """البحث في Bing لإيميلات متعلقة بالنطاق"""
        # تسجيل بدء البحث بوضوح
        logger.info(f"🚀 BING SEARCH STARTING for domain: {domain}")
        logger.info(
            f"Bing search options: pages={self.opts.get('bing_pages', 2)}, "
            f"delay={self.opts.get('bing_delay', 3.0)}"
        )
        logger.info(f"Bing proxy setting: {self.opts.get('proxy', 'No proxy')}")

        domain = base.normalize_domain(domain)

        # إعدادات قابلة للتخصيص
        max_pages = int(self.opts.get("bing_pages", 2))
        base_delay = float(self.opts.get("bing_delay", 3.0))
        max_results = min(limit, max_pages * 10)

        user_agent = self._get_user_agent()
        proxy = self._get_proxy()

        # استعلامات بحث محددة
        queries = self._generate_queries(domain)

        all_emails: Set[str] = set()
        session = requests.Session()

        logger.info(f"Bing: Using {len(queries)} queries, {max_pages} pages each")
        logger.info(f"Bing queries: {queries}")

        for query_idx, query in enumerate(queries):
            if len(all_emails) >= max_results:
                break

            logger.info(
                f"Bing processing query {query_idx + 1}/{len(queries)}: '{query}'"
            )

            for page in range(max_pages):
                if len(all_emails) >= max_results:
                    break

                try:
                    logger.info(f"Bing search: '{query}' - Page {page + 1}/{max_pages}")
                    emails = self._search_bing_page(
                        session=session,
                        query=query,
                        page=page,
                        user_agent=user_agent,
                        proxy=proxy,
                    )

                    new_emails = [e for e in emails if e not in all_emails]
                    if new_emails:
                        logger.info(
                            f"Bing: Found {len(new_emails)} new emails from query '{query}'"
                        )
                        for email in new_emails[:3]:  # تسجيل أول 3 إيميلات فقط
                            logger.debug(f"Bing email found: {email}")

                    all_emails.update(emails)

                    # تأخير ذكي بين الطلبات
                    delay = random.uniform(base_delay, base_delay + 2.0)
                    logger.debug(f"Bing: Sleeping for {delay:.1f} seconds")
                    time.sleep(delay)

                except Exception as e:
                    logger.error(f"Bing search error for query '{query}': {str(e)}")
                    logger.exception("Bing error details:")
                    continue

        # تصفية وترتيب النتائج
        filtered = base.filter_by_domain(list(all_emails), domain)
        sorted_emails = self._sort_emails_by_quality(filtered)

        logger.info(
            f"✅ BING SEARCH COMPLETED. Found {len(sorted_emails)} emails for {domain}"
        )
        if sorted_emails:
            logger.info(f"Bing emails found: {sorted_emails[:5]}")  # أول 5 إيميلات فقط

        return sorted_emails[:limit]

    def _generate_queries(self, domain: str) -> List[str]:
        """إنشاء استعلامات بحث ذكية لـ Bing"""
        queries = [
            f'site:{domain} "@{domain}"',
            f'site:{domain} "email"',
            f'site:{domain} "contact"',
            f'"{domain}" "@gmail.com"',
            f'"{domain}" "@yahoo.com"',
        ]

        # تقليل الاستعلامات لبعض النطاقات
        if domain.endswith(".ye"):
            logger.warning(f"Domain {domain} ends with .ye - using limited queries")
            queries = [f'site:{domain} "contact"']  # استعلام واحد فقط

        return queries

    def _search_bing_page(
        self, session, query: str, page: int, user_agent: str, proxy: str = None
    ) -> List[str]:
        """البحث في صفحة محددة من Bing"""
        first = page * 10 + 1
        encoded_query = quote_plus(query)
        url = f"https://www.bing.com/search?q={encoded_query}&first={first}"

        headers = self._create_headers(user_agent)
        proxies = self._create_proxies(proxy)

        logger.info(f"Bing requesting: {url}")
        logger.debug(f"Bing headers: {headers}")

        try:
            response = session.get(
                url, headers=headers, proxies=proxies, timeout=15, allow_redirects=True
            )

            logger.info(f"Bing response status: {response.status_code}")

            if response.status_code == 200:
                # التحقق من حظر Bing
                response_text = response.text

                if "Our systems have detected unusual traffic" in response_text:
                    logger.warning(
                        "⚠️ Bing has detected unusual traffic. Consider using proxies."
                    )
                    return []

                if "Please show you're not a robot" in response_text:
                    logger.warning("⚠️ Bing CAPTCHA triggered.")
                    return []

                # استخراج الإيميلات
                emails = base.extract_emails(response.text)
                logger.debug(f"Bing raw emails found: {len(emails)}")

                # تنظيف النتائج
                cleaned_emails = []
                for email in emails:
                    email = email.strip().lower()
                    if self._is_valid_email(email):
                        cleaned_emails.append(email)

                logger.info(
                    f"✅ Bing found {len(cleaned_emails)} valid emails on page {page}"
                )
                return cleaned_emails

            elif response.status_code == 429:
                logger.warning(
                    "⏸️ Bing: Rate limited (429). Increasing delay to 10 seconds..."
                )
                time.sleep(10)
            elif response.status_code == 503:
                logger.warning("⏸️ Bing: Service unavailable (503).")
                time.sleep(10)
            else:
                logger.warning(f"⚠️ Bing: HTTP {response.status_code}")

        except requests.exceptions.ConnectionError as e:
            logger.error(f"🔌 Bing connection error: {str(e)}")
        except requests.exceptions.Timeout:
            logger.warning("⏰ Bing: Request timeout (15s)")
        except Exception as e:
            logger.error(f"❌ Bing request error: {str(e)}")
            logger.exception("Bing exception details:")

        return []

    def _create_headers(self, user_agent: str) -> Dict[str, str]:
        """إنشاء headers واقعية لـ Bing"""
        return {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

    def _create_proxies(self, proxy):
        """إنشاء proxies dictionary"""
        if not proxy:
            logger.debug("Bing: No proxy configured")
            return None

        try:
            if isinstance(proxy, str):
                parsed = urlparse(proxy)
            else:
                parsed = proxy

            if parsed.scheme and parsed.netloc:
                scheme = parsed.scheme
                proxy_url = f"{scheme}://{parsed.netloc}"
                logger.info(f"Bing using proxy: {proxy_url}")
                return {"http": proxy_url, "https": proxy_url}
        except Exception as e:
            logger.error(f"Error creating proxies: {str(e)}")

        return None

    def _get_user_agent(self) -> str:
        """الحصول على User-Agent عشوائي"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]

        ua = self.opts.get("useragent") or self.opts.get("userAgent")
        selected_ua = ua or random.choice(user_agents)
        logger.debug(f"Bing User-Agent: {selected_ua[:50]}...")
        return selected_ua

    def _get_proxy(self):
        """معالجة الـ proxy"""
        proxy = self.opts.get("proxy")
        if not proxy:
            logger.debug("Bing: No proxy configured")
            return None

        if hasattr(proxy, "scheme") and hasattr(proxy, "netloc"):
            logger.debug(f"Bing: Using proxy {proxy.scheme}://{proxy.netloc}")
            return proxy

        if isinstance(proxy, str):
            try:
                parsed = urlparse(proxy)
                logger.debug(
                    f"Bing: Parsed proxy string: {parsed.scheme}://{parsed.netloc}"
                )
                return parsed
            except Exception as e:
                logger.error(f"Bing: Error parsing proxy string: {str(e)}")
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
        }

        domain = email.split("@")[-1].lower()
        if domain in disposable_domains:
            return False

        # تجاهل الإيميلات غير الصالحة
        if ".." in email or " " in email:
            return False

        # تحقق من صيغة الإيميل الأساسية
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(email_regex, email))

    def _sort_emails_by_quality(self, emails: List[str]) -> List[str]:
        """ترتيب الإيميلات حسب الجودة"""

        def email_score(email: str) -> int:
            score = 0

            if re.match(r"^[a-z]+\.[a-z]+@", email):
                score += 3
            elif re.match(r"^[a-z]+@", email):
                score += 2

            corporate_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}
            domain = email.split("@")[-1]
            if domain not in corporate_domains:
                score += 5

            if not re.match(r"^\d+", email.split("@")[0]):
                score += 1

            return score

        return sorted(emails, key=email_score, reverse=True)


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
