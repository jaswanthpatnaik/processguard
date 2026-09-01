"""Platform detection and safe dynamic import utilities."""

import importlib
import os
import sys
from typing import Any, Optional


def is_windows() -> bool:
    """Checks if current operating system is Windows."""
    return sys.platform == "win32" or os.name == "nt"


def is_linux() -> bool:
    """Checks if current operating system is Linux / POSIX."""
    return sys.platform.startswith("linux") or (os.name == "posix" and not sys.platform.startswith("darwin"))


def safe_import(module_name: str) -> Optional[Any]:
    """Dynamically imports a module safely, returning None if not found."""
    try:
        return importlib.import_module(module_name)
    except (ImportError, Exception):
        return None
