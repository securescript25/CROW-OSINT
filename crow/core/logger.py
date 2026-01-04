"""Logger setup for CROW."""
import sys

from loguru import logger

logger.remove()
logger.add(
    sys.stderr,
    format="{time} | {level} | {name}:{function}:{line} - {message}",
    level="INFO",
    colorize=True,
)
