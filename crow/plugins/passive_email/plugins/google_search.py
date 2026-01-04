# crow/plugins/passive_email/plugins/google_search.py
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
    Engine name: google
    Searches Google for emails related to a domain.
    Opts supported:
      - google_pages: number of pages to scrape (default: 2)
      - google_delay: delay between requests in seconds (default: 3-6)
    """

    def __init__(self, harvester, opts: Dict):
        self.harvester = harvester
        self.opts = opts or {}
        # تسجيل الخيارات عند التهيئة
        logger.info(f"Google plugin initialized with opts: {list(self.opts.keys())}")
        self.harvester.register_plugin("google", {"search": self.search})

    def search(self, domain: str, limit: int = 100) -> List[str]:
        """البحث في Google لإيميلات متعلقة بالنطاق"""
        # تسجيل بدء البحث بوضوح
        logger.info(f"🚀 GOOGLE SEARCH STARTING for domain: {domain}")
        logger.info(
            f"Google search options: pages={self.opts.get('google_pages', 2)}, "
            f"delay={self.opts.get('google_delay', 3.0)}"
        )
        logger.info(f"Google proxy setting: {self.opts.get('proxy', 'No proxy')}")

        domain = base.normalize_domain(domain)

        # إعدادات قابلة للتخصيص
        max_pages = int(self.opts.get("google_pages", 2))
        base_delay = float(self.opts.get("google_delay", 3.0))
        max_results = min(limit, max_pages * 10)

        user_agent = self._get_user_agent()
        proxy = self._get_proxy()

        # استعلامات بحث ذكية (محدودة)
        queries = self._generate_queries(domain)

        all_emails: Set[str] = set()
        session = requests.Session()

        logger.info(f"Google: Using {len(queries)} queries, {max_pages} pages each")
        logger.info(f"Google queries: {queries}")

        for query_idx, query in enumerate(queries):
            if len(all_emails) >= max_results:
                break

            logger.info(
                f"Google processing query {query_idx + 1}/{len(queries)}: '{query}'"
            )

            for page in range(max_pages):
                if len(all_emails) >= max_results:
                    break

                try:
                    logger.info(
                        f"Google search: '{query}' - Page {page + 1}/{max_pages}"
                    )
                    emails = self._search_google_page(
                        session=session,
                        query=query,
                        page=page,
                        user_agent=user_agent,
                        proxy=proxy,
                    )

                    new_emails = [e for e in emails if e not in all_emails]
                    if new_emails:
                        logger.info(
                            f"Google: Found {len(new_emails)} new emails from query '{query}'"
                        )
                        for email in new_emails[:3]:  # تسجيل أول 3 إيميلات فقط
                            logger.debug(f"Google email found: {email}")

                    all_emails.update(emails)

                    # تأخير ذكي بين الطلبات (أطول لـ Google)
                    delay = random.uniform(base_delay, base_delay + 3.0)
                    logger.debug(f"Google: Sleeping for {delay:.1f} seconds")
                    time.sleep(delay)

                except requests.exceptions.TooManyRedirects:
                    logger.warning("Google: Too many redirects, moving to next query")
                    break
                except requests.exceptions.ProxyError as e:
                    logger.error(f"Google: Proxy error: {str(e)}")
                    break
                except requests.exceptions.Timeout:
                    logger.warning("Google: Request timeout, continuing...")
                    time.sleep(5)
                    continue
                except Exception as e:
                    logger.error(f"Google search error: {str(e)}")
                    logger.exception("Google error details:")  # تسجيل traceback كامل
                    continue

        # تصفية وترتيب النتائج
        filtered = base.filter_by_domain(list(all_emails), domain)
        sorted_emails = self._sort_emails_by_quality(filtered)

        logger.info(
            f"✅ GOOGLE SEARCH COMPLETED. Found {len(sorted_emails)} emails for {domain}"
        )
        if sorted_emails:
            logger.info(
                f"Google emails found: {sorted_emails[:5]}"
            )  # أول 5 إيميلات فقط

        return sorted_emails[:limit]

    def _generate_queries(self, domain: str) -> List[str]:
        """إنشاء استعلامات بحث ذكية"""
        # استعلامات أساسية (محدودة لتجنب الحظر)
        queries = [
            f'site:{domain} "@{domain}" email',
            f'site:{domain} "contact"',
            f'"{domain}" "@gmail.com" OR "@yahoo.com"',
        ]

        # إذا كان النطاق .ye (مشاكل محتملة مع Google)
        if domain.endswith(".ye"):
            logger.warning(f"Domain {domain} ends with .ye - using limited queries")
            queries = [f'site:{domain} "contact"']  # استعلام واحد فقط

        return queries

    def _search_google_page(
        self, session, query: str, page: int, user_agent: str, proxy: str = None
    ) -> List[str]:
        """البحث في صفحة محددة من Google"""
        start = page * 10
        encoded_query = quote_plus(query)
        url = f"https://www.google.com/search?q={encoded_query}&start={start}&num=10"

        headers = self._create_headers(user_agent)
        proxies = self._create_proxies(proxy)

        logger.info(f"Google requesting: {url}")
        logger.debug(f"Google headers: {headers}")

        try:
            response = session.get(
                url,
                headers=headers,
                proxies=proxies,
                timeout=20,  # زيادة timeout
                allow_redirects=True,
            )

            logger.info(f"Google response status: {response.status_code}")

            if response.status_code == 200:
                # التحقق من أننا لم نحصل على صفحة حظر
                response_text = response.text.lower()

                if "detected unusual traffic" in response_text:
                    logger.warning(
                        "⚠️ Google has detected unusual traffic. Consider using proxies or increasing delay."
                    )
                    return []

                if "captcha" in response_text:
                    logger.warning(
                        "⚠️ Google CAPTCHA triggered. Increasing delay or using proxies recommended."
                    )
                    return []

                if "our systems have detected unusual traffic" in response_text:
                    logger.warning("⚠️ Google: Rate limit detected. Waiting longer...")
                    time.sleep(10)
                    return []

                # استخراج الإيميلات
                emails = base.extract_emails(response.text)
                logger.debug(f"Google raw emails found: {len(emails)}")

                # تنظيف النتائج
                cleaned_emails = []
                for email in emails:
                    email = email.strip().lower()
                    if self._is_valid_email(email):
                        cleaned_emails.append(email)

                logger.info(
                    f"✅ Google found {len(cleaned_emails)} valid emails on page {page}"
                )
                return cleaned_emails

            elif response.status_code == 429:
                logger.warning(
                    "⏸️ Google: Rate limited (429). Increasing delay to 15 seconds..."
                )
                time.sleep(15)
            elif response.status_code == 503:
                logger.warning(
                    "⏸️ Google: Service unavailable (503). Possible blocking."
                )
                time.sleep(10)
            else:
                logger.warning(f"⚠️ Google: HTTP {response.status_code}")

        except requests.exceptions.ConnectionError as e:
            logger.error(f"🔌 Google connection error: {str(e)}")
        except requests.exceptions.Timeout:
            logger.warning("⏰ Google: Request timeout (20s)")
        except Exception as e:
            logger.error(f"❌ Google request error: {str(e)}")
            logger.exception("Google exception details:")

        return []

    def _create_headers(self, user_agent: str) -> Dict[str, str]:
        """إنشاء headers واقعية"""
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
            "Cache-Control": "max-age=0",
        }

    def _create_proxies(self, proxy):
        """إنشاء proxies dictionary"""
        if not proxy:
            logger.debug("Google: No proxy configured")
            return None

        try:
            if isinstance(proxy, str):
                parsed = urlparse(proxy)
            else:
                parsed = proxy

            if parsed.scheme and parsed.netloc:
                scheme = parsed.scheme
                proxy_url = f"{scheme}://{parsed.netloc}"
                logger.info(f"Google using proxy: {proxy_url}")
                return {"http": proxy_url, "https": proxy_url}
        except Exception as e:
            logger.error(f"Error creating proxies: {str(e)}")

        return None

    def _get_user_agent(self) -> str:
        """الحصول على User-Agent عشوائي"""
        user_agents = [
            # Chrome على Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Firefox على Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            # Safari على Mac
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            # Chrome على Linux
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]

        ua = self.opts.get("useragent") or self.opts.get("userAgent")
        selected_ua = ua or random.choice(user_agents)
        logger.debug(f"Google User-Agent: {selected_ua[:50]}...")
        return selected_ua

    def _get_proxy(self):
        """معالجة الـ proxy"""
        proxy = self.opts.get("proxy")
        if not proxy:
            logger.debug("Google: No proxy configured")
            return None

        if hasattr(proxy, "scheme") and hasattr(proxy, "netloc"):
            logger.debug(f"Google: Using proxy {proxy.scheme}://{proxy.netloc}")
            return proxy

        if isinstance(proxy, str):
            try:
                parsed = urlparse(proxy)
                logger.debug(
                    f"Google: Parsed proxy string: {parsed.scheme}://{parsed.netloc}"
                )
                return parsed
            except Exception as e:
                logger.error(f"Google: Error parsing proxy string: {str(e)}")
                return None

        return None

    def _is_valid_email(self, email: str) -> bool:
        """التحقق من صحة الإيميل"""
        if not email or "@" not in email:
            return False

        # تجاهل الإيميلات الواضحة غير المرغوبة
        unwanted_patterns = [
            r"\.png$",
            r"\.jpg$",
            r"\.gif$",  # ملفات صور
            r"example\.com$",
            r"test\.com$",  # نطاقات تجريبية
            r"noreply@",
            r"no-reply@",  # بريد آلي
            r"bounce@",
            r"admin@server\.",  # بريد الخادم
            r"\.\.",
            r"\s",  # نقطتين متتاليتين أو مسافات
        ]

        for pattern in unwanted_patterns:
            if re.search(pattern, email, re.IGNORECASE):
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
            "sharklasers.com",
            "grr.la",
            "maildrop.cc",
        }

        domain = email.split("@")[-1].lower()
        if domain in disposable_domains:
            return False

        # تحقق من صيغة الإيميل الأساسية
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(email_regex, email))

    def _sort_emails_by_quality(self, emails: List[str]) -> List[str]:
        """ترتيب الإيميلات حسب الجودة"""

        def email_score(email: str) -> int:
            score = 0

            # الإيميلات الشخصية أفضل
            if re.match(r"^[a-z]+\.[a-z]+@", email):  # john.doe@
                score += 3
            elif re.match(r"^[a-z]+@", email):  # john@
                score += 2

            # نطاقات الشركات أفضل
            corporate_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}
            domain = email.split("@")[-1]
            if domain not in corporate_domains:
                score += 5  # نطاق مخصص للشركة

            # تجاهل الأرقام في بداية الإيميل
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
