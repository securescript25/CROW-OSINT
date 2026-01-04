# crow/plugins/passive_social/plugin.py
from __future__ import annotations

import importlib
import pkgutil
import re
import time
from typing import Any, Dict, List, Optional, Type

from crow.core.bases import PassivePlugin
from crow.core.logger import logger as default_logger
from crow.core.models import PluginOutput


class PassiveSocialPlugin(PassivePlugin):
    # لازم يكون الاسم هو اللي تستدعيه بالأمر: -p social
    name = "social"
    description = "Search usernames across social networks (Sherlock-style modules)"

    def __init__(self, config=None, logger_obj=None):
        # ✅ لا تستدعي super().__init__(config, logger) لأن PassivePlugin عندك غالبًا بدون __init__
        self.config = config
        self.logger = logger_obj or default_logger

        self.version = "1.0.0"
        self.modules: List[Any] = []
        self._loaded = False

    # ----------------------------
    # تحميل موديلات السوشيال
    # ----------------------------
    def load_modules(self) -> None:
        """
        Loads engine modules from:
        crow/plugins/passive_social/plugins/*.py

        Important:
        - import as package so relative imports work (from .base import SocialBase)
        """
        if self._loaded:
            return

        pkg_name = "crow.plugins.passive_social.plugins"

        try:
            pkg = importlib.import_module(pkg_name)
        except Exception as e:
            self.logger.error(
                f"[social] cannot import plugins package '{pkg_name}': {e}"
            )
            self._loaded = True
            return

        # استورد SocialBase من base.py (مصدر واحد موثوق)
        try:
            base_mod = importlib.import_module(f"{pkg_name}.base")
            SocialBase = getattr(base_mod, "SocialBase", None)
        except Exception as e:
            self.logger.error(f"[social] cannot import SocialBase: {e}")
            self._loaded = True
            return

        if SocialBase is None:
            self.logger.error("[social] SocialBase not found in plugins/base.py")
            self._loaded = True
            return

        loaded_any = False

        for _, module_short_name, _ in pkgutil.iter_modules(pkg.__path__):
            if module_short_name in ("__init__", "base"):
                continue

            full_mod_name = f"{pkg_name}.{module_short_name}"

            try:
                mod = importlib.import_module(full_mod_name)
            except Exception as e:
                self.logger.error(
                    f"[social] failed importing module '{full_mod_name}': {e}"
                )
                continue

            # ابحث عن أي class يرث من SocialBase
            for _, obj in vars(mod).items():
                if not isinstance(obj, type):
                    continue
                if obj is SocialBase:
                    continue

                try:
                    if issubclass(obj, SocialBase):
                        try:
                            inst = obj(self.config, self.logger)
                        except TypeError:
                            # fallback لو التوقيع مختلف
                            inst = obj()
                        self.modules.append(inst)
                        loaded_any = True
                        self.logger.info(
                            f"[social] Loaded engine: {full_mod_name}.{obj.__name__}"
                        )
                except Exception:
                    continue

        if not loaded_any:
            self.logger.warning(
                "[social] No engine modules loaded. Put engines in: passive_social/plugins/*.py"
            )

        self._loaded = True

    # ----------------------------
    # استخراج username
    # ----------------------------
    def extract_username(self, target: str) -> str:
        if not target:
            return ""

        # username مباشر
        if not target.startswith(("http://", "https://")):
            return target.strip()

        patterns = {
            "twitter": r"twitter\.com/([^/?]+)",
            "github": r"github\.com/([^/?]+)",
            "instagram": r"instagram\.com/([^/?]+)",
            "linkedin": r"linkedin\.com/in/([^/?]+)",
            "facebook": r"facebook\.com/([^/?]+)",
            "youtube": r"youtube\.com/(?:c/|channel/|user/|@)?([^/?]+)",
            "tiktok": r"tiktok\.com/@([^/?]+)",
            "reddit": r"reddit\.com/user/([^/?]+)",
        }

        for _, pat in patterns.items():
            m = re.search(pat, target, re.IGNORECASE)
            if m:
                return m.group(1).split("/")[0]

        # fallback: آخر جزء من الرابط
        parts = target.rstrip("/").split("/")
        return parts[-1].split("?")[0] if parts else target

    # ----------------------------
    # نقطة دخول CROW: run()
    # ----------------------------
    def run(self, target: str, **kwargs) -> PluginOutput:
        """
        يرجع PluginOutput مثل باقي البلجنات (dns/email).
        kwargs اختياري: timeout (ثواني)
        """
        self.load_modules()

        output = PluginOutput(plugin=self.name)

        username = self.extract_username(target)
        if not username:
            output.errors.append("Invalid target / cannot extract username.")
            return output

        timeout = float(kwargs.get("timeout", 30.0))

        start = time.time()
        self.logger.info(
            f"[social] Running social search for: {username} (timeout={timeout}s)"
        )

        if not self.modules:
            output.errors.append("No social engine modules loaded.")
            return output

        # شغّل كل engine (مثل SherlockModule)
        for engine in self.modules:
            engine_name = engine.__class__.__name__

            try:
                # إذا engine يدعم timeout، مرره
                if hasattr(engine, "timeout"):
                    try:
                        engine.timeout = int(timeout)
                    except Exception:
                        pass

                if not hasattr(engine, "collect"):
                    continue

                data_list = engine.collect(username) or []

                for d in data_list:
                    # نرجع دائمًا نتائج حتى لو exists=False
                    output.results.append(
                        {
                            "plugin": self.name,
                            "type": "SOCIAL",
                            "engine": engine_name,
                            "platform": d.get("platform", "unknown"),
                            "url": d.get("url", ""),
                            "username": d.get("username", username),
                            "exists": bool(d.get("exists", False)),
                            "status_code": int(d.get("status_code", 0) or 0),
                            "response_time": float(d.get("response_time", 0) or 0),
                        }
                    )

            except Exception as e:
                self.logger.error(f"[social] Engine {engine_name} failed: {e}")
                output.errors.append(f"{engine_name}: {e}")

        self.logger.info(
            f"[social] Done in {time.time()-start:.2f}s. Results={len(output.results)}"
        )
        return output
