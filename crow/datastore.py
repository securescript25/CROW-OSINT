from typing import Any, Dict

from crow.core.logger import logger


class GlobalStore:
    """متغيرات موحَّدة بين كل الـ plugins."""

    _store: Dict[str, Any] = {}

    @classmethod
    def set(cls, key: str, value: Any) -> None:
        cls._store[key] = value
        logger.debug(f"GlobalStore.set: {key} = {value}")

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        return cls._store.get(key, default)

    @classmethod
    def list_vars(cls) -> Dict[str, Any]:
        return cls._store.copy()

    @classmethod
    def clear(cls) -> None:
        cls._store.clear()
        logger.debug("GlobalStore cleared")
