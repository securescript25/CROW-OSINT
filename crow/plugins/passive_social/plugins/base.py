from abc import ABC, abstractmethod
from typing import Any, Dict, List


class SocialBase(ABC):
    def __init__(self, config, logger):
        self.config = config or {}
        self.logger = logger

    @abstractmethod
    def collect(self, **kwargs) -> List[Dict[str, Any]]:
        pass

    def validate_target(self, target: str) -> bool:
        return bool(target and isinstance(target, str) and len(target.strip()) > 0)
