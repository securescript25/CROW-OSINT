from abc import ABC, abstractmethod
from typing import Any, Dict, List


class SocialBase(ABC):
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    @abstractmethod
    def collect(self, target: str) -> List[Dict[str, Any]]:
        """جمع المعلومات من الشبكات الاجتماعية"""
        pass

    def validate_target(self, target: str) -> bool:
        """التحقق من صحة الهدف"""
        return bool(target and isinstance(target, str) and len(target.strip()) > 0)
