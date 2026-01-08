import ast
import os

from crow.core.logger import logger


def run_script(script_path: str) -> None:
    """تشغيل سكريبت Python يتفاعل مع CROW."""
    logger.info(f"Running script: {script_path}")
    try:
        with open(script_path, "r", encoding="utf-8") as f:
            code = f.read()
        # نُنفذ الكود في بيئة محمية
        exec(code, globals(), locals())
    except Exception as e:
        logger.error(f"Script failed: {e}")
