"""Utils package initialization."""
from utils.platform_check import is_windows, is_linux, safe_import
from utils.process_helpers import safe_getattr, normalize_path, is_name_spoofed
from utils.logger import get_logger, setup_logging

__all__ = [
    "is_windows",
    "is_linux",
    "safe_import",
    "safe_getattr",
    "normalize_path",
    "is_name_spoofed",
    "get_logger",
    "setup_logging",
]
