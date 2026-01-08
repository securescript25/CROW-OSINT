import subprocess

from crow.core.logger import logger


def run_external_command(cmd: str) -> str:
    """تشغيل أمر خارجي مثل !nmap أو !ping."""
    logger.info(f"Running external command: {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"External command failed: {e}")
        return f"Error: {e}"
