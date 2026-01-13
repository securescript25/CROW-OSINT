from typing import Any, Dict, List


class GuessModule:
    name = "guess"

    def __init__(self, config, logger):
        self.config = config or {}
        self.logger = logger

    def collect(self, domain: str, brand: str) -> List[Dict[str, Any]]:
        b = (brand or "").strip()
        if not b:
            return []

        # theHarvester-like candidates (multi-platform)
        return [
            {"platform": "Twitter", "url": f"https://twitter.com/{b}", "source": "guess"},
            {"platform": "Instagram", "url": f"https://instagram.com/{b}", "source": "guess"},
            {"platform": "LinkedIn", "url": f"https://www.linkedin.com/company/{b}/", "source": "guess"},
            {"platform": "Facebook", "url": f"https://facebook.com/{b}", "source": "guess"},
            {"platform": "YouTube", "url": f"https://youtube.com/@{b}", "source": "guess"},
            {"platform": "GitHub", "url": f"https://github.com/{b}", "source": "guess"},
        ]
