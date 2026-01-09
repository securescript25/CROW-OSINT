"""
crow/plugins/active_robots/plugin.py
أداة بسيطة لجلب وتحليل robots.txt بدون تعقيدات
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urljoin

import requests

from crow.core.bases import ActivePlugin
from crow.core.models import PluginOutput

class active_robots(ActivePlugin):
    """
    أداة بسيطة لجلب وتحليل robots.txt
    فقط إحضار وتحليل البيانات الأساسية
    """
    
    name = "active_robots"
    description = "Simple robots.txt fetcher and parser"
    version = "1.0.0"
    
    def __init__(self, config=None, logger_obj=None):
        super().__init__(config, logger_obj)
        self.config = config
        self.timeout = getattr(config, 'timeout', 10)
        self.user_agent = getattr(config, 'user_agent', 
                                 "Mozilla/5.0 (CROW-Robots-Fetcher/1.0)")
    
    def run(self, target: str, **kwargs) -> PluginOutput:
        """
        جلب وتحليل robots.txt بشكل بسيط
        
        Args:
            target: الهدف (مثال: example.com)
            
        Returns:
            PluginOutput: نتائج بسيطة
        """
        results = []
        errors = []
        
        try:
            # تطبيع الهدف
            base_url = self._normalize_url(target)
            
            # جلب robots.txt
            robots_url = urljoin(base_url, "/robots.txt")
            
            # محاولة HTTPS أولاً
            content, status, final_url = self._fetch_robots(robots_url)
            
            if content:
                # تحليل بسيط
                parsed_data = self._simple_parse(content)
                
                results.append({
                    "plugin": self.name,
                    "target": target,
                    "robots_url": final_url,
                    "status_code": status,
                    "exists": True,
                    "content_length": len(content),
                    "raw_content": content,
                    "parsed_data": parsed_data
                })
            else:
                # محاولة HTTP إذا فشل HTTPS
                http_url = robots_url.replace('https://', 'http://')
                content, status, final_url = self._fetch_robots(http_url)
                
                if content:
                    parsed_data = self._simple_parse(content)
                    
                    results.append({
                        "plugin": self.name,
                        "target": target,
                        "robots_url": final_url,
                        "status_code": status,
                        "exists": True,
                        "content_length": len(content),
                        "raw_content": content,
                        "parsed_data": parsed_data,
                        "note": "Fetched via HTTP (HTTPS failed)"
                    })
                else:
                    # robots.txt غير موجود
                    results.append({
                        "plugin": self.name,
                        "target": target,
                        "robots_url": robots_url,
                        "status_code": status,
                        "exists": False,
                        "note": f"robots.txt not found (HTTP {status})"
                    })
        
        except Exception as e:
            errors.append(f"Error: {str(e)}")
        
        return PluginOutput(
            plugin=self.name,
            results=results,
            errors=errors
        )
    
    def _normalize_url(self, target: str) -> str:
        """إضافة http:// إذا لم يكن موجوداً"""
        if not target.startswith(('http://', 'https://')):
            return f"https://{target}"
        return target
    
    def _fetch_robots(self, url: str) -> tuple:
        """جلب محتوى robots.txt"""
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent},
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                return response.text, response.status_code, response.url
            else:
                return None, response.status_code, response.url
                
        except Exception:
            return None, 0, url
    
    def _simple_parse(self, content: str) -> Dict:
        """تحليل بسيط لـ robots.txt"""
        lines = content.splitlines()
        
        # تحليل كل سطر
        rules = []
        sitemaps = []
        user_agents = set()
        current_agent = "*"
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # تخطي الأسطر الفارغة والتعليقات
            if not line or line.startswith('#'):
                continue
            
            # إزالة التعليقات في نهاية السطر
            if '#' in line:
                line = line.split('#')[0].strip()
            
            # تقسيم السطر
            if ':' in line:
                parts = line.split(':', 1)
                directive = parts[0].strip().lower()
                value = parts[1].strip()
                
                rule = {
                    "line": i,
                    "directive": directive,
                    "value": value,
                    "raw": line
                }
                
                if directive == "user-agent":
                    current_agent = value
                    user_agents.add(value)
                    rule["user_agent"] = value
                    rules.append(rule)
                
                elif directive == "disallow":
                    rule["user_agent"] = current_agent
                    rule["path"] = value
                    rules.append(rule)
                
                elif directive == "allow":
                    rule["user_agent"] = current_agent
                    rule["path"] = value
                    rules.append(rule)
                
                elif directive == "sitemap":
                    sitemaps.append(value)
                    rule["sitemap_url"] = value
                    rules.append(rule)
                
                elif directive == "crawl-delay":
                    rule["user_agent"] = current_agent
                    rule["delay"] = value
                    rules.append(rule)
                
                elif directive == "host":
                    rule["host"] = value
                    rules.append(rule)
                
                else:
                    rule["user_agent"] = current_agent
                    rules.append(rule)
        
        # إحصاءات بسيطة
        disallow_count = sum(1 for r in rules if r.get("directive") == "disallow")
        allow_count = sum(1 for r in rules if r.get("directive") == "allow")
        
        return {
            "total_rules": len(rules),
            "user_agents": list(user_agents),
            "disallow_count": disallow_count,
            "allow_count": allow_count,
            "sitemaps": sitemaps,
            "rules": rules,
            "line_count": len(lines)
        }