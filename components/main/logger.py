import sys
from loguru import logger
from rich.console import Console
from rich.logging import RichHandler

console = Console()
status = None
mode = "SCANNING"
color = 'cyan'
attack = ''


def configure_logging():
    logger.remove()
    
    ORANGE = "\x1b[38;2;255;165;0m"
    PURPLE = "\x1b[38;2;128;0;128m"
    
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
        filter=lambda rec: (
            rec["level"].no <= logger.level("INFO").no
            and rec["level"].name != "SCANNING"
        ),
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
    
def logger_error(msg: str):
    status.stop()
    logger.error(msg)
    status.start()


def start_status():
    global status
    status = console.status(f"[{color}]{mode} {attack} | initializing...", spinner="dots")
    status.__enter__()


def update_status(msg: str):
    if status:
        status.update(f"[{color}]{mode} {attack} | {msg}")

def attack_status():
    global status
    global mode
    global color
    mode = "ATTACKING"
    color = 'yellow'
    status = console.status(f"[{color}]{mode}  {attack} | initializing...", spinner="dots")
    status.__enter__()
    
def attack_update(mod):
    global attack
    attack = mod
    
def stop_status():
    global status
    if status:
        status.__exit__(None, None, None)
        status = None


configure_logging()
