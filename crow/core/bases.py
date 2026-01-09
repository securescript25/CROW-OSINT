"""Base classes for all plugins."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from crow.core.models import PluginOutput


class PassivePlugin(ABC):
    """Base for all passive recon plugins."""

    name: str = ""
    description: str = ""
    version: str = "1.0.0"

    def __init__(self, config: Any = None, logger: Any = None):
        # مهم: البلوقنز تعتمد على هذي القيم
        self.config = config
        self.logger = logger

    @abstractmethod
    def run(self, target: str, **kwargs) -> PluginOutput:
        """Run the plugin and return results."""
        raise NotImplementedError


class ActivePlugin(ABC):
    """Base for all active recon plugins."""

    name: str = ""
    description: str = ""
    version: str = "1.0.0"

    def __init__(self, config: Any = None, logger: Any = None):
        # مهم: البلوقنز الـ Active (مثل bhp) تمرر (config, logger)
        self.config = config
        self.logger = logger

    @abstractmethod
    def run(self, target: str, port: int = None, **kwargs) -> PluginOutput:
        """Run the plugin and return results."""
        raise NotImplementedError


class ReporterPlugin(ABC):
    """Base for all output reporters."""

    name: str = ""
    description: str = ""
    version: str = "1.0.0"

    def __init__(self, config: Any = None, logger: Any = None):
        self.config = config
        self.logger = logger

    @abstractmethod
    def write(self, data: List[PluginOutput], out_path: str) -> str:
        """Write data to file and return path."""
        raise NotImplementedError
