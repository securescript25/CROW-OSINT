"""Dynamic plugin loader for CROW."""
import importlib
import inspect
import os
import pkgutil
from typing import Any, Dict, List, Optional, Set, Type

from crow.core.bases import ActivePlugin, PassivePlugin, ReporterPlugin
from crow.core.logger import logger


class PluginRegistry:
    """Registry for all plugins."""

    _passive: Dict[str, Type[PassivePlugin]] = {}
    _active: Dict[str, Type[ActivePlugin]] = {}
    _reporters: Dict[str, Type[ReporterPlugin]] = {}

    # Plugin information cache
    _plugin_info: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def _safe_import(cls, dotted: str):
        try:
            return importlib.import_module(dotted)
        except Exception as e:
            logger.debug(f"Import failed: {dotted} -> {e}")
            return None

    @classmethod
    def _modules_for_plugin_dir(cls, plugin_dir: str) -> List[Any]:
        """
        Return a list of modules to inspect for a plugin directory.

        We support (and inspect ALL if available):
        - crow.plugins.<plugin_dir>.plugin       (standard plugin.py)  [PREFERRED]
        - crow.plugins.<plugin_dir>              (package __init__.py)
        - crow.plugins.<plugin_dir>.<plugin_dir> (rare alternative layout)

        Why prefer plugin.py first?
        Because many packages import classes in __init__.py, which can cause duplicate registration.
        """
        mods: List[Any] = []

        # 1) plugin.py first (IMPORTANT)
        m = cls._safe_import(f"crow.plugins.{plugin_dir}.plugin")
        if m is not None:
            mods.append(m)

        # 2) package
        m = cls._safe_import(f"crow.plugins.{plugin_dir}")
        if m is not None:
            mods.append(m)

        # 3) direct module named as folder
        m = cls._safe_import(f"crow.plugins.{plugin_dir}.{plugin_dir}")
        if m is not None:
            mods.append(m)

        # remove duplicates by object id
        uniq: List[Any] = []
        seen: Set[int] = set()
        for mm in mods:
            if id(mm) in seen:
                continue
            seen.add(id(mm))
            uniq.append(mm)

        return uniq

    @classmethod
    def _register_plugin_info(cls, pname: str, ptype: str, obj, plugin_dir: str):
        cls._plugin_info[pname] = {
            "type": ptype,
            "description": getattr(obj, "description", "No description"),
            "version": getattr(obj, "version", "1.0.0"),
            "module": plugin_dir,
            "python_module": getattr(obj, "__module__", "unknown"),
        }

    @classmethod
    def autoload(cls):
        """Auto-discover and register all plugins."""
        pkg = importlib.import_module("crow.plugins")

        # Clear existing registries
        cls._passive.clear()
        cls._active.clear()
        cls._reporters.clear()
        cls._plugin_info.clear()

        logger.info("Starting plugin autoload...")

        plugins_path = pkg.__path__[0]
        plugin_dirs: List[str] = [
            d
            for d in os.listdir(plugins_path)
            if os.path.isdir(os.path.join(plugins_path, d))
        ]

        logger.debug(f"Found plugin directories: {plugin_dirs}")

        for plugin_dir in plugin_dirs:
            if plugin_dir.startswith(".") or plugin_dir == "__pycache__":
                continue

            modules = cls._modules_for_plugin_dir(plugin_dir)
            if not modules:
                logger.debug(
                    f"Skipping {plugin_dir}: cannot import package/plugin modules"
                )
                continue

            found_any = False

            # Inspect all candidate modules for this plugin_dir
            for module in modules:
                try:
                    for _, obj in inspect.getmembers(module, inspect.isclass):
                        # Only allow classes that belong to this plugin package
                        obj_mod = getattr(obj, "__module__", "") or ""
                        if not obj_mod.startswith(f"crow.plugins.{plugin_dir}"):
                            continue

                        # Passive
                        if (
                            issubclass(obj, PassivePlugin)
                            and obj is not PassivePlugin
                            and hasattr(obj, "name")
                        ):
                            pname = obj.name

                            # ✅ prevent duplicates (plugin.py first wins)
                            if pname in cls._passive:
                                continue

                            cls._passive[pname] = obj
                            cls._register_plugin_info(pname, "passive", obj, plugin_dir)

                            logger.info(
                                f"Registered passive plugin: {pname} ({plugin_dir})"
                            )
                            found_any = True
                            continue

                        # Active
                        if (
                            issubclass(obj, ActivePlugin)
                            and obj is not ActivePlugin
                            and hasattr(obj, "name")
                        ):
                            pname = obj.name

                            # ✅ prevent duplicates (plugin.py first wins)
                            if pname in cls._active:
                                continue

                            cls._active[pname] = obj
                            cls._register_plugin_info(pname, "active", obj, plugin_dir)

                            logger.info(
                                f"Registered active plugin: {pname} ({plugin_dir})"
                            )
                            found_any = True
                            continue

                except Exception as e:
                    logger.error(
                        f"Error inspecting module {getattr(module, '__name__', module)}: {e}"
                    )

            if not found_any:
                logger.warning(f"No plugin classes found in: {plugin_dir}")

        # Load reporter plugins
        try:
            rep_pkg = importlib.import_module("crow.reporters")
            logger.debug("Loading reporter plugins...")

            for _, name, _ in pkgutil.iter_modules(rep_pkg.__path__):
                module = cls._safe_import(f"crow.reporters.{name}")
                if module is None:
                    logger.warning(f"Skipping reporter '{name}': import error")
                    continue

                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, ReporterPlugin)
                        and obj is not ReporterPlugin
                        and hasattr(obj, "name")
                    ):
                        pname = obj.name
                        if pname in cls._reporters:
                            continue

                        cls._reporters[pname] = obj
                        cls._plugin_info[pname] = {
                            "type": "reporter",
                            "description": getattr(obj, "description", "No description"),
                            "version": getattr(obj, "version", "1.0.0"),
                            "module": name,
                            "python_module": getattr(obj, "__module__", "unknown"),
                        }
                        logger.info(f"Registered reporter plugin: {pname}")

        except ModuleNotFoundError:
            logger.warning("crow.reporters module not found, skipping reporter plugins")
        except Exception as e:
            logger.error(f"Error loading reporter plugins: {e}")

        logger.info(
            "Plugin autoload complete. "
            f"Passive: {len(cls._passive)}, "
            f"Active: {len(cls._active)}, "
            f"Reporters: {len(cls._reporters)}"
        )

    # ====== list ======
    @classmethod
    def list_passive(cls) -> List[str]:
        return sorted(cls._passive.keys())

    @classmethod
    def list_active(cls) -> List[str]:
        return sorted(cls._active.keys())

    @classmethod
    def list_reporters(cls) -> List[str]:
        return sorted(cls._reporters.keys())

    @classmethod
    def list_all(cls) -> Dict[str, List[str]]:
        return {
            "passive": cls.list_passive(),
            "active": cls.list_active(),
            "reporters": cls.list_reporters(),
        }

    # ====== get ======
    @classmethod
    def get_passive(cls, name: str) -> Optional[Type[PassivePlugin]]:
        return cls._passive.get(name)

    @classmethod
    def get_active(cls, name: str) -> Optional[Type[ActivePlugin]]:
        return cls._active.get(name)

    @classmethod
    def get_reporter(cls, name: str) -> Optional[Type[ReporterPlugin]]:
        return cls._reporters.get(name)

    @classmethod
    def get_plugin_info(cls, name: str) -> Dict[str, Any]:
        if name in cls._plugin_info:
            return cls._plugin_info[name].copy()
        return {}

    # ====== create instances ======
    @classmethod
    def create_passive(cls, name: str, config, logger_obj) -> PassivePlugin:
        plugin_class = cls.get_passive(name)
        if not plugin_class:
            raise ValueError(f"Passive plugin '{name}' not found")
        return plugin_class(config, logger_obj)

    @classmethod
    def create_active(cls, name: str, config, logger_obj) -> ActivePlugin:
        plugin_class = cls.get_active(name)
        if not plugin_class:
            raise ValueError(f"Active plugin '{name}' not found")
        return plugin_class(config, logger_obj)

    @classmethod
    def create_reporter(cls, name: str, config, logger_obj) -> ReporterPlugin:
        plugin_class = cls.get_reporter(name)
        if not plugin_class:
            raise ValueError(f"Reporter plugin '{name}' not found")
        return plugin_class(config, logger_obj)

    # ====== refresh ======
    @classmethod
    def refresh(cls):
        logger.info("Refreshing plugin registry...")
        cls.autoload()
