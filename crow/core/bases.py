"""Base classes for all plugins."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from crow.core.models import PluginOutput


class PassivePlugin(ABC):
    """Base for all passive recon plugins."""

    name: str = ""
    description: str = ""

    @abstractmethod
    def run(self, target: str, **kwargs) -> PluginOutput:
        """Run the plugin and return results."""
        pass


class ActivePlugin(ABC):
    """Base for all active recon plugins."""

    name: str = ""
    description: str = ""

    @abstractmethod
    def run(self, target: str, port: int = None, **kwargs) -> PluginOutput:
        """Run the plugin and return results."""
        pass


class ReporterPlugin(ABC):
    """Base for all output reporters."""

    name: str = ""
    description: str = ""

    @abstractmethod
    def write(self, data: List[PluginOutput], out_path: str) -> str:
        """Write data to file and return path."""
        pass
