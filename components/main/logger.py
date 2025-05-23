import sys
from loguru import logger

def configure_logging():
    logger.remove()
    
    ORANGE = "\x1b[38;2;255;165;0m"
    
    logger.level("INFO", color="<green>")
    logger.level("ATTACK", no=25, color="<yellow>")
    logger.level("LOW", no=30, color="<blue>")
    logger.level("MEDIUM", no=35, color=ORANGE)
    logger.level("HIGH", no=41, color="<red>")
    logger.level("VULN", no=45, color="<magenta>")

    logger.add(
        sys.stdout,
        level="DEBUG",
        format="<level>{level}</level> | {message}",
        filter=lambda rec: rec["level"].no <= logger.level("INFO").no,
    )

    logger.add(
        sys.stdout,
        level="ATTACK",
        format="<level>{level}</level> | {message}",
        filter=lambda rec: rec["level"].no == logger.level("ATTACK").no,
    )

    logger.add(
        sys.stdout,
        level="ERROR",
        format="<level>{level}</level> | {file.name}:{line} - {message}",
        filter=lambda rec: rec["level"].no == logger.level("ERROR").no,
    )

    logger.add(
        sys.stdout,
        level="LOW",
        format="<level>{level}</level> | {message}",
        filter=lambda rec: rec["level"].no == logger.level("LOW").no,
    )

    logger.add(
        sys.stdout,
        level="MEDIUM",
        format="<level>{level}</level> | {message}",
        filter=lambda rec: rec["level"].no == logger.level("MEDIUM").no,
    )

    logger.add(
        sys.stdout,
        level="HIGH",
        format="<level>{level}</level> | {message}",
        filter=lambda rec: rec["level"].no == logger.level("HIGH").no,
    )

    logger.add(
        sys.stdout,
        level="CRITICAL",
        format="<level>{level}</level> | {message}",
        filter=lambda rec: rec["level"].no == logger.level("CRITICAL").no,
    )

    logger.add(
        sys.stdout,
        level="VULN",
        format="{message}",
        filter=lambda rec: rec["level"].no == logger.level("VULN").no,
    )

configure_logging()
