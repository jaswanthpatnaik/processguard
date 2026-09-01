"""Process inspection helper functions with robust exception handling."""

from pathlib import Path
from typing import Any, List, Optional
import psutil


def safe_getattr(proc: psutil.Process, attr: str, default: Any = None) -> Any:
    """Safely retrieves a process attribute using psutil handling all process lifecycle errors."""
    if proc is None:
        return default

    try:
        if attr == "cmdline":
            res = proc.cmdline()
            return " ".join(res) if isinstance(res, list) else str(res or "")
        elif attr == "parent_name":
            parent = proc.parent()
            return parent.name() if parent else "N/A"
        elif attr == "parent_pid":
            return proc.ppid()
        elif attr == "memory_mb":
            mem_info = proc.memory_info()
            return round(mem_info.rss / (1024 * 1024), 2)
        elif attr == "cpu_percent":
            # Avoid blocking calls
            return round(proc.cpu_percent(interval=None), 2)
        elif hasattr(proc, attr):
            val = getattr(proc, attr)
            return val() if callable(val) else val
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError, Exception):
        pass

    return default


def normalize_path(path_str: Optional[str]) -> str:
    """Normalizes executable path string across Windows and POSIX platforms."""
    if not path_str or not isinstance(path_str, str):
        return ""
    try:
        return str(Path(path_str).resolve())
    except Exception:
        return path_str.strip()


def is_name_spoofed(proc_name: str, exe_path: str) -> bool:
    """Checks whether the process executable name matches process name."""
    if not proc_name or not exe_path:
        return False

    try:
        clean_name = proc_name.lower().rstrip(".exe")
        exe_basename = Path(exe_path).name.lower().rstrip(".exe")
        return clean_name != exe_basename
    except Exception:
        return False
