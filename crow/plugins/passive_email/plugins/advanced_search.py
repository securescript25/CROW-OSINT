# crow/plugins/passive_email/plugins/advanced_search.py
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
    Engine name: advanced
    Advanced email harvesting using multiple techniques and sources.
    Opts supported:
      - real_emails_only: true/false (default: false)
      - max_techniques: number of techniques to use (default: 3)
    """

    def __init__(self, harvester, opts: Dict):
        self.harvester = harvester
        self.opts = opts or {}
        self.harvester.register_plugin("advanced", {"search": self.search})

    def search(self, domain: str, limit: int = 100) -> List[str]:
        """البحث المتقدم لإيميلات متعلقة بالنطاق"""
        logger.info(f"Advanced search starting for domain: {domain}")
        domain = base.normalize_domain(domain)

        # الحصول على اسم الشركة من النطاق
        company_name = self._extract_company_name(domain)

        # إعدادات البحث
        real_emails_only = bool(self.opts.get("real_emails_only", False))
        max_techniques = int(self.opts.get("max_techniques", 3))
        max_results = limit

        user_agent = self._get_user_agent()
        proxy = self._get_proxy()

        all_emails: Set[str] = set()
        session = requests.Session()

        # تقنيات البحث المتقدمة
        techniques = [
            ("site_crawl", self._search_site_crawl),
            ("github", self._search_github),
            ("google_dorks", self._search_google_dorks),
        ]

        # إذا كان real_emails_only = true، لا نضيف الأنماط الاجتماعية
        if not real_emails_only:
            techniques.append(("educated_guesses", self._generate_educated_guesses))

        # تقييد عدد التقنيات
        techniques = techniques[:max_techniques]

        logger.info(
            f"Advanced: Using {len(techniques)} techniques: {[t[0] for t in techniques]}"
        )

        for tech_idx, (tech_name, tech_func) in enumerate(techniques):
            if len(all_emails) >= max_results:
                break

            try:
                logger.info(
                    f"Advanced: Running {tech_name} technique ({tech_idx + 1}/{len(techniques)})..."
                )

                if tech_name == "educated_guesses":
                    emails = tech_func(domain, company_name)
                else:
                    emails = tech_func(session, domain, user_agent, proxy)

                new_emails = [e for e in emails if e not in all_emails]
                if new_emails:
                    logger.info(
                        f"Advanced: Found {len(new_emails)} new emails from {tech_name}"
                    )

                all_emails.update(emails)

                # تأخير بين التقنيات
                if tech_idx < len(techniques) - 1:
                    delay = random.uniform(2, 4)
                    logger.debug(
                        f"Advanced: Sleeping for {delay:.1f} seconds between techniques"
                    )
                    time.sleep(delay)

            except Exception as e:
                logger.error(f"Advanced {tech_name} error: {str(e)}")
                continue

        # تصفية وترتيب النتائج
        filtered = base.filter_by_domain(list(all_emails), domain)
        sorted_emails = self._sort_emails_by_quality(filtered)

        logger.info(
            f"Advanced search completed. Found {len(sorted_emails)} emails for {domain}"
        )
        return sorted_emails[:limit]

    def _extract_company_name(self, domain: str) -> str:
        """استخراج اسم الشركة من النطاق"""
        # إزالة TLDs
        name = domain.split(".")[0]

        # تحويل الأحرف الخاصة
        name = re.sub(r"[^a-zA-Z0-9]", "", name)

        return name.lower()

    def _search_site_crawl(
        self, session, domain: str, user_agent: str, proxy: str = None
    ) -> List[str]:
        """زحف الموقع الفعلي لايجاد إيميلات حقيقية"""
        logger.info(f"Advanced: Crawling {domain} for real emails")

        urls_to_crawl = [
            f"https://{domain}/contact",
            f"https://{domain}/contact-us",
            f"https://{domain}/contactus",
            f"https://{domain}/about",
            f"https://{domain}/team",
            f"https://{domain}/staff",
            f"https://{domain}/faculty",
            f"https://{domain}/administration",
            f"https://{domain}/contact.php",
            f"https://{domain}/contact.html",
        ]

        emails: Set[str] = set()

        for url in urls_to_crawl:
            try:
                logger.debug(f"Advanced: Crawling {url}")
                response = session.get(
                    url,
                    headers={"User-Agent": user_agent},
                    proxies=self._create_proxies(proxy),
                    timeout=10,
                    allow_redirects=True,
                )

                if response.status_code == 200:
                    found_emails = base.extract_emails(response.text)
                    for email in found_emails:
                        email = email.strip().lower()
                        if self._is_valid_email(email) and domain in email:
                            emails.add(email)
                            logger.debug(f"Advanced: Found email in {url}: {email}")

                time.sleep(1)  # تأخير بين الطلبات

            except Exception as e:
                logger.debug(f"Advanced: Could not crawl {url}: {str(e)}")
                continue

        logger.info(f"Advanced: Site crawl found {len(emails)} emails")
        return list(emails)

    def _search_github(
        self, session, domain: str, user_agent: str, proxy: str = None
    ) -> List[str]:
        """البحث في GitHub للإيميلات"""
        logger.info(f"Advanced: Searching GitHub for {domain}")

        emails: Set[str] = set()

        # استعلامات GitHub (محدودة)
        queries = [
            f'"{domain}" email',
            f'"{domain}" @{domain}',
        ]

        for query in queries:
            try:
                github_emails = self._search_github_page(
                    session, query, user_agent, proxy
                )
                emails.update(github_emails)
                time.sleep(3)  # احترام rate limits
            except Exception as e:
                logger.error(f"Advanced GitHub search error: {str(e)}")
                continue

        logger.info(f"Advanced: GitHub search found {len(emails)} emails")
        return list(emails)

    def _search_github_page(
        self, session, query: str, user_agent: str, proxy: str = None
    ) -> List[str]:
        """البحث في صفحة GitHub"""
        encoded_query = quote_plus(query)
        url = f"https://github.com/search?q={encoded_query}&type=code"

        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        proxies = self._create_proxies(proxy)

        try:
            response = session.get(url, headers=headers, proxies=proxies, timeout=15)

            if response.status_code == 200:
                emails = base.extract_emails(response.text)
                cleaned_emails = []
                for email in emails:
                    email = email.strip().lower()
                    if self._is_valid_email(email):
                        cleaned_emails.append(email)
                return cleaned_emails
            elif response.status_code == 429:
                logger.warning("Advanced: GitHub rate limited.")
            else:
                logger.warning(f"Advanced: GitHub HTTP {response.status_code}")

        except Exception as e:
            logger.error(f"Advanced GitHub request error: {str(e)}")

        return []

    def _search_google_dorks(
        self, session, domain: str, user_agent: str, proxy: str = None
    ) -> List[str]:
        """استخدام Google Dorks متقدمة"""
        logger.info(f"Advanced: Using Google Dorks for {domain}")

        emails: Set[str] = set()

        # Google Dorks محددة
        dorks = [
            f'site:{domain} "email"',
            f'site:{domain} "contact"',
            f'site:{domain} "mailto:"',
            f'site:{domain} "@{domain}"',
        ]

        for dork in dorks:
            try:
                dork_emails = self._search_google_dork(session, dork, user_agent, proxy)
                emails.update(dork_emails)
                time.sleep(random.uniform(4, 7))  # تأخير أطول
            except Exception as e:
                logger.error(f"Advanced Google dork error: {str(e)}")
                continue

        logger.info(f"Advanced: Google Dorks found {len(emails)} emails")
        return list(emails)

    def _search_google_dork(
        self, session, dork: str, user_agent: str, proxy: str = None
    ) -> List[str]:
        """البحث باستخدام Google Dork"""
        encoded_dork = quote_plus(dork)
        url = f"https://www.google.com/search?q={encoded_dork}&num=10"

        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        proxies = self._create_proxies(proxy)

        try:
            response = session.get(url, headers=headers, proxies=proxies, timeout=15)

            if response.status_code == 200:
                emails = base.extract_emails(response.text)
                return [e.strip().lower() for e in emails if self._is_valid_email(e)]

        except Exception:
            pass

        return []

    def _generate_educated_guesses(self, domain: str, company_name: str) -> List[str]:
        """توليد إيميلات متعلمة بناءً على أنماط واقعية"""
        logger.info(f"Advanced: Generating educated guesses for {domain}")

        emails: Set[str] = set()

        # 1. الإيميلات الإدارية القياسية (الأكثر شيوعاً)
        standard_emails = [
            f"info@{domain}",
            f"contact@{domain}",
            f"admin@{domain}",
            f"support@{domain}",
            f"webmaster@{domain}",
            f"postmaster@{domain}",
            f"hostmaster@{domain}",
        ]

        # 2. إيميلات الأقسام (خاصة بالجامعات)
        department_emails = [
            f"admissions@{domain}",
            f"registrar@{domain}",
            f"academic@{domain}",
            f"library@{domain}",
            f"research@{domain}",
            f"faculty@{domain}",
            f"student@{domain}",
            f"hr@{domain}",
            f"it@{domain}",
            f"finance@{domain}",
        ]

        # 3. إيميلات بناءً على اسم النطاق
        company_based_emails = [
            f"{company_name}@{domain}",
            f"admin-{company_name}@{domain}",
            f"support-{company_name}@{domain}",
        ]

        # جمع جميع الإيميلات المقترحة
        all_suggestions = standard_emails + department_emails + company_based_emails

        # إضافة إيميلات شخصية واقعية (للجامعات)
        if any(edu in domain for edu in [".edu.", ".ac.", ".sch."]):
            common_names = ["mohammed", "ahmed", "ali", "fatima", "sara", "omar"]
            for name in common_names[:3]:  # أول 3 أسماء فقط
                all_suggestions.append(f"{name}@{domain}")
                all_suggestions.append(f"{name}.{company_name}@{domain}")

        # تصفية الإيميلات الصالحة
        for email in all_suggestions:
            email = email.lower().strip()
            if self._is_valid_email(email):
                emails.add(email)

        logger.info(f"Advanced: Generated {len(emails)} educated guesses")
        return list(emails)

    def _create_proxies(self, proxy):
        """إنشاء proxies dictionary"""
        if not proxy:
            return None

        try:
            if isinstance(proxy, str):
                parsed = urlparse(proxy)
            else:
                parsed = proxy

            if parsed.scheme and parsed.netloc:
                scheme = parsed.scheme
                proxy_url = f"{scheme}://{parsed.netloc}"
                return {"http": proxy_url, "https": proxy_url}
        except Exception as e:
            logger.error(f"Advanced: Error creating proxies: {str(e)}")

        return None

    def _get_user_agent(self) -> str:
        """الحصول على User-Agent"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]

        ua = self.opts.get("useragent") or self.opts.get("userAgent")
        return ua or random.choice(user_agents)

    def _get_proxy(self):
        """معالجة الـ proxy"""
        proxy = self.opts.get("proxy")
        if not proxy:
            logger.debug("Advanced: No proxy configured")
            return None

        if hasattr(proxy, "scheme") and hasattr(proxy, "netloc"):
            logger.debug(f"Advanced: Using proxy {proxy.scheme}://{proxy.netloc}")
            return proxy

        if isinstance(proxy, str):
            try:
                parsed = urlparse(proxy)
                logger.debug(
                    f"Advanced: Parsed proxy string: {parsed.scheme}://{parsed.netloc}"
                )
                return parsed
            except Exception as e:
                logger.error(f"Advanced: Error parsing proxy string: {str(e)}")
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

            # الإيميلات الإدارية القياسية أفضل
            standard_emails = {"info@", "contact@", "admin@", "support@", "webmaster@"}
            if email.split("@")[0] in standard_emails:
                score += 10

            # نطاقات الشركات أفضل
            corporate_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}
            domain = email.split("@")[-1]
            if domain not in corporate_domains:
                score += 5

            # الإيميلات الطويلة (أكثر واقعية) أفضل
            if len(email.split("@")[0]) > 5:
                score += 2

            # الإيميلات التي تحتوي على نقاط أفضل
            if "." in email.split("@")[0]:
                score += 1

            return score

        return sorted(emails, key=email_score, reverse=True)


# تسجيل الـ logger
try:
    from crow.core.logger import logger
except ImportError:
    import logging

    logger = logging.getLogger(__name__)
