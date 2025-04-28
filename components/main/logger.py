import sys
from loguru import logger

def configure_logging():
    logger.remove()
    logger.level("INFO", color="<green>")

    logger.add(
        sys.stdout,
        level="DEBUG",
        format="<level>{level}</level> | {message}",
        filter=lambda r: r["level"].no <= logger.level("INFO").no,
    )

    logger.add(
        sys.stdout,
        level="WARNING",
        format="<level>{level}</level> | {message}",
        filter=lambda r: r["level"].no == logger.level("WARNING").no,
    )

    logger.add(
        sys.stdout,
        level="ERROR",
        format="<level>{level}</level> | {file.name}:{line} - {message}",
    )

configure_logging()
