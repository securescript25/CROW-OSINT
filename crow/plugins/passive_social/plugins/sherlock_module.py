import json
import os
import re
import time
from typing import Any, Dict, List

import requests
from requests_futures.sessions import FuturesSession

from .base import SocialBase


class SherlockModule(SocialBase):
    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.name = "sherlock_module"
        self.timeout = 30
        self.max_workers = 10
        self.load_sites_data()

    def load_sites_data(self):
        """تحميل بيانات مواقع التواصل من ملف JSON"""
        try:
            data_file = os.path.join(
                os.path.dirname(__file__), "..", "resources", "data.json"
            )

            with open(data_file, "r", encoding="utf-8") as f:
                self.sites_data = json.load(f)

            self.logger.info(f"Loaded {len(self.sites_data)} social sites")

        except Exception as e:
            self.logger.error(f"Failed to load sites data: {e}")
            # بيانات افتراضية أساسية
            self.sites_data = {
                "Twitter": {
                    "url": "https://twitter.com/{}",
                    "urlMain": "https://twitter.com/",
                    "errorType": "status_code",
                    "errorCode": 404,
                },
                "GitHub": {
                    "url": "https://github.com/{}",
                    "urlMain": "https://github.com/",
                    "errorType": "status_code",
                    "errorCode": 404,
                },
                "Instagram": {
                    "url": "https://instagram.com/{}",
                    "urlMain": "https://instagram.com/",
                    "errorType": "status_code",
                    "errorCode": 404,
                },
            }

    def collect(self, username: str) -> List[Dict[str, Any]]:
        """البحث عن اسم المستخدم عبر مواقع التواصل"""
        results = []

        if not self.validate_target(username):
            self.logger.error(f"Invalid username: {username}")
            return results

        self.logger.info(f"Searching for username: {username}")

        # إعداد الجلسة المتوازية
        session = FuturesSession(max_workers=self.max_workers)
        futures = {}

        # إعداد الطلبات لكل موقع
        for site_name, site_info in self.sites_data.items():
            try:
                url = site_info["url"].format(username)
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }

                # إضافة هيدرات إضافية إذا كانت موجودة
                if "headers" in site_info:
                    headers.update(site_info["headers"])

                # اختيار طريقة الطلب
                request_method = site_info.get("request_method", "GET").upper()

                if request_method == "HEAD":
                    future = session.head(url, headers=headers, timeout=self.timeout)
                elif request_method == "POST":
                    future = session.post(url, headers=headers, timeout=self.timeout)
                else:
                    future = session.get(url, headers=headers, timeout=self.timeout)

                futures[future] = (site_name, site_info, url)

                # تأجيل بسيط لتجنب الحظر
                time.sleep(0.05)

            except Exception as e:
                self.logger.error(f"Error preparing request for {site_name}: {e}")

        # معالجة النتائج
        for future in futures:
            site_name, site_info, url = futures[future]

            try:
                response = future.result()
                exists = self.check_username_exists(response, site_info)

                result_data = {
                    "platform": site_name,
                    "url": url,
                    "username": username,
                    "exists": exists,
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds()
                    if hasattr(response, "elapsed")
                    else 0,
                    "error_type": site_info.get("errorType", "unknown"),
                }

                if exists:
                    self.logger.info(f"✓ Found on {site_name}: {url}")
                else:
                    self.logger.debug(f"✗ Not found on {site_name}")

                results.append(result_data)

            except requests.exceptions.Timeout:
                self.logger.warning(f"Timeout checking {site_name}")
                results.append(
                    {
                        "platform": site_name,
                        "url": url,
                        "username": username,
                        "exists": False,
                        "status_code": 408,
                        "error": "timeout",
                    }
                )

            except Exception as e:
                self.logger.error(f"Error checking {site_name}: {e}")
                results.append(
                    {
                        "platform": site_name,
                        "url": url,
                        "username": username,
                        "exists": False,
                        "status_code": 500,
                        "error": str(e),
                    }
                )

        return results

    def check_username_exists(self, response, site_info):
        """التحقق من وجود اسم المستخدم بناءً على نوع الخطأ"""
        error_type = site_info.get("errorType", "status_code")

        if error_type == "status_code":
            error_codes = site_info.get("errorCode", [])
            if isinstance(error_codes, int):
                error_codes = [error_codes]

            if error_codes:
                return response.status_code not in error_codes
            else:
                # الأكواد 2xx تعني الوجود
                return 200 <= response.status_code < 300

        elif error_type == "message":
            error_msg = site_info.get("errorMsg", "")
            if error_msg:
                if isinstance(error_msg, list):
                    for msg in error_msg:
                        if msg in response.text:
                            return False
                    return True
                else:
                    return error_msg not in response.text
            return True

        elif error_type == "response_url":
            error_url = site_info.get("errorUrl", "")
            if error_url:
                return error_url not in response.url
            return True

        else:
            # نوع غير معروف، نفترض الوجود
            return True

    def get_supported_platforms(self):
        """الحصول على قائمة المنصات المدعومة"""
        return list(self.sites_data.keys())
