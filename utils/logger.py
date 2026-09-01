"""Logging setup for ProcessGuard with colorama support."""

import logging
import os
from pathlib import Path
import sys
import colorama

colorama.init(autoreset=True)

_LOGGER: logging.Logger = None


def setup_logging(log_file: str = "data/processguard.log", level: int = logging.INFO) -> logging.Logger:
    """Configures system-wide logging to file and stdout."""
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER

    logger = logging.getLogger("ProcessGuard")
    logger.setLevel(level)

    log_path = Path(log_file)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(level)
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(name)s: %(message)s")
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except Exception:
        pass

    # Stream handler for stdout
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(level)
    sh_formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    sh.setFormatter(sh_formatter)
    logger.addHandler(sh)

    _LOGGER = logger
    return _LOGGER


def get_logger() -> logging.Logger:
    """Returns logger instance or initializes default."""
    global _LOGGER
    if _LOGGER is None:
        return setup_logging()
    return _LOGGER
