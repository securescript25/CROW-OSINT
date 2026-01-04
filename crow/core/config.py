"""Configuration loader for CROW."""
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

DEFAULT_CONFIG = {
    "timeout": 10,
    "rate_limit": 1,
    "max_retries": 3,
    "output_format": "json",
    "output_dir": "./reports",
    "user_agent": "CROW-OSINT/0.1.0",
}


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from file or environment variables."""
    config = DEFAULT_CONFIG.copy()

    # Load from file if exists
    if config_path and config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            file_config = yaml.safe_load(f) or {}
            config.update(file_config)

    # Override from environment variables
    config["timeout"] = int(os.getenv("CROW_TIMEOUT", config["timeout"]))
    config["rate_limit"] = int(os.getenv("CROW_RATE_LIMIT", config["rate_limit"]))
    config["output_dir"] = os.getenv("CROW_OUTPUT_DIR", config["output_dir"])

    return config
