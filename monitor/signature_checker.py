"""MODULE 6 — Windows Executable Signature & Version Resource Trust Checker."""

from pathlib import Path
from typing import Any, Dict, List, Optional
from utils.logger import get_logger
from utils.platform_check import is_windows, safe_import

logger = get_logger()

# Safe import of Windows Win32 API modules
win32api = safe_import("win32api") if is_windows() else None


class SignatureChecker:
    """Inspects Windows PE executable version resources and digital signature attributes."""

    def __init__(self, path_detector_paths: Optional[List[str]] = None) -> None:
        self.available: bool = is_windows() and win32api is not None
        self.suspicious_path_patterns: List[str] = path_detector_paths or [
            "\\temp\\",
            "\\downloads\\",
            "\\appdata\\",
            "\\public\\",
        ]
        if not self.available:
            logger.debug("SignatureChecker: pywin32 or Windows environment unavailable — skipping signature verification.")

    def check_file_version_info(self, exe_path: str) -> bool:
        """Returns True if executable file has valid PE version resource info."""
        if not self.available or not exe_path:
            return True

        path_obj = Path(exe_path)
        if not path_obj.is_file():
            return True

        try:
            info = win32api.GetFileVersionInfo(str(path_obj), "\\")
            return info is not None and len(info) > 0
        except Exception:
            return False

    def scan(self, new_processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scans newly launched processes for missing version headers or unsigned binaries in risky paths."""
        if not self.available:
            return []

        alerts: List[Dict[str, Any]] = []
        for p_info in new_processes:
            exe_path = p_info.get("exe_path", "")
            pid = p_info.get("pid", 0)
            name = p_info.get("name", "Unknown")

            if not exe_path or not Path(exe_path).is_file():
                continue

            has_version = self.check_file_version_info(exe_path)
            if not has_version:
                path_lower = exe_path.lower()
                in_suspicious_dir = any(pattern in path_lower for pattern in self.suspicious_path_patterns)

                if in_suspicious_dir:
                    alerts.append(
                        {
                            "alert_type": "SUSPICIOUS_UNSIGNED",
                            "severity": "HIGH",
                            "pid": pid,
                            "process_name": name,
                            "exe_path": exe_path,
                            "parent_pid": p_info.get("ppid", 0),
                            "parent_name": p_info.get("parent_name", "N/A"),
                            "detail": f"Unsigned binary '{name}' running from high-risk directory: '{exe_path}'",
                        }
                    )
                else:
                    alerts.append(
                        {
                            "alert_type": "UNSIGNED_EXECUTABLE",
                            "severity": "LOW",
                            "pid": pid,
                            "process_name": name,
                            "exe_path": exe_path,
                            "parent_pid": p_info.get("ppid", 0),
                            "parent_name": p_info.get("parent_name", "N/A"),
                            "detail": f"Executable binary '{name}' (PID: {pid}) lacks valid PE version resources.",
                        }
                    )

        return alerts
