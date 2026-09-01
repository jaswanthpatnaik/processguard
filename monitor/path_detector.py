"""MODULE 3 — Suspicious Path, Hollowed Process & Name Spoofing Detector."""

from pathlib import Path
from typing import Any, Dict, List
from utils.logger import get_logger
from utils.platform_check import is_windows
from utils.process_helpers import is_name_spoofed, normalize_path

logger = get_logger()

# Legitimate Microsoft System and Vendor paths to exclude from suspicious directory alerts
TRUSTED_PATH_WHITELIST: List[str] = [
    r"c:\programdata\microsoft\windows defender",
    r"c:\programdata\microsoft\windows defender advanced threat protection",
    r"c:\programdata\microsoft\windows security health",
    r"c:\programdata\package cache",
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
]

# Protected Windows kernel virtual containers and system tasks with no accessible disk path
KNOWN_SYSTEM_PROCESSES = {
    "",
    "system",
    "registry",
    "memory compression",
    "secure system",
    "idle",
    "system idle process",
    "interrupts",
}


class PathDetector:
    """Detects executables running from untrusted directories, hollowed binaries, or spoofed process names."""

    def __init__(self, suspicious_paths_cfg: Dict[str, List[str]]) -> None:
        self.win_paths: List[str] = suspicious_paths_cfg.get("windows", [])
        self.linux_paths: List[str] = suspicious_paths_cfg.get("linux", [])

    def inspect_process(self, p_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Inspects a single process dictionary for path anomalies."""
        alerts: List[Dict[str, Any]] = []
        pid = p_info.get("pid", 0)
        name = p_info.get("name", "Unknown")
        exe_path = normalize_path(p_info.get("exe_path", ""))
        ppid = p_info.get("ppid", 0)
        parent_name = p_info.get("parent_name", "N/A")
        name_lower = name.lower().strip()

        # 1. Hollowed process detection (running process with no exe path)
        # Skip protected Windows kernel processes (PID <= 128 or known system containers)
        if not exe_path:
            if pid <= 128 or name_lower in KNOWN_SYSTEM_PROCESSES:
                return alerts

            alerts.append(
                {
                    "alert_type": "SUSPICIOUS_PATH",
                    "severity": "CRITICAL",
                    "pid": pid,
                    "process_name": name,
                    "exe_path": "NONE (Hollowed / Hidden)",
                    "parent_pid": ppid,
                    "parent_name": parent_name,
                    "detail": f"Process '{name}' (PID: {pid}) has no accessible executable path on disk (potential process hollowing).",
                }
            )
            return alerts

        # 2. Suspicious Path Detection
        path_lower = exe_path.lower()
        is_trusted = any(tp in path_lower for tp in TRUSTED_PATH_WHITELIST)

        if not is_trusted:
            targets = self.win_paths if is_windows() else self.linux_paths
            for sub in targets:
                sub_clean = sub.lower().replace("\\\\", "\\")
                if sub_clean in path_lower:
                    # Determine severity based on path
                    if "public" in path_lower or "/dev/shm" in path_lower:
                        sev = "CRITICAL"
                    elif "roaming" in path_lower or "/var/tmp" in path_lower:
                        sev = "HIGH"
                    else:
                        sev = "MEDIUM"

                    alerts.append(
                        {
                            "alert_type": "SUSPICIOUS_PATH",
                            "severity": sev,
                            "pid": pid,
                            "process_name": name,
                            "exe_path": exe_path,
                            "parent_pid": ppid,
                            "parent_name": parent_name,
                            "detail": f"Process '{name}' running from suspicious directory pattern '{sub}': '{exe_path}'",
                        }
                    )
                    break

        # 3. Process Name Spoofing Detection
        if exe_path and is_name_spoofed(name, exe_path):
            alerts.append(
                {
                    "alert_type": "SUSPICIOUS_PATH",
                    "severity": "HIGH",
                    "pid": pid,
                    "process_name": name,
                    "exe_path": exe_path,
                    "parent_pid": ppid,
                    "parent_name": parent_name,
                    "detail": f"Process name '{name}' mismatches underlying executable filename '{Path(exe_path).name}' (Name Spoofing).",
                }
            )

        return alerts

    def scan(self, live_processes: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scans all live processes against path security rules."""
        all_alerts: List[Dict[str, Any]] = []
        for pid, p_info in live_processes.items():
            alerts = self.inspect_process(p_info)
            if alerts:
                all_alerts.extend(alerts)
        return all_alerts
