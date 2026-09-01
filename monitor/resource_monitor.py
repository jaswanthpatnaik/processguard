"""MODULE 4 — Abnormal Resource Usage & Cryptominer / Ransomware Monitor."""

from collections import defaultdict, deque
from typing import Any, Dict, List, Tuple
from database.db_manager import DBManager
from utils.logger import get_logger

logger = get_logger()


class ResourceMonitor:
    """Monitors per-process CPU and Memory consumption to detect cryptominers or resource abuse."""

    def __init__(self, thresholds_cfg: Dict[str, int], db: DBManager) -> None:
        self.cpu_threshold: float = float(thresholds_cfg.get("cpu_alert_percent", 80))
        self.mem_threshold: float = float(thresholds_cfg.get("memory_alert_mb", 500))
        self.sustained_cycles: int = int(thresholds_cfg.get("cpu_sustained_cycles", 3))
        self.db: DBManager = db

        # Rolling deque history for CPU readings: pid -> deque([cpu_perc1, cpu_perc2, ...], maxlen=5)
        self.cpu_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=5))

    def scan(self, live_processes: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scans live processes and updates resource rolling statistics."""
        alerts: List[Dict[str, Any]] = []
        active_pids = set(live_processes.keys())

        # Clean up history for dead PIDs
        dead_pids = set(self.cpu_history.keys()) - active_pids
        for dead_pid in dead_pids:
            del self.cpu_history[dead_pid]

        for pid, p_info in live_processes.items():
            name = p_info.get("name", "Unknown")
            # Exclude Windows system kernel tasks from high resource alerts
            if pid in (0, 4) or name.lower() in ("system idle process", "system", "memcompression"):
                continue

            exe_path = p_info.get("exe_path", "")
            ppid = p_info.get("ppid", 0)
            parent_name = p_info.get("parent_name", "N/A")
            cpu = float(p_info.get("cpu_percent", 0.0))
            mem = float(p_info.get("memory_mb", 0.0))

            # Record history
            self.cpu_history[pid].append(cpu)

            # Check sustained high CPU
            history = self.cpu_history[pid]
            if len(history) >= self.sustained_cycles:
                recent_readings = list(history)[-self.sustained_cycles :]
                if all(val >= self.cpu_threshold for val in recent_readings):
                    avg_cpu = round(sum(recent_readings) / len(recent_readings), 1)
                    alerts.append(
                        {
                            "alert_type": "HIGH_CPU",
                            "severity": "MEDIUM",
                            "pid": pid,
                            "process_name": name,
                            "exe_path": exe_path,
                            "parent_pid": ppid,
                            "parent_name": parent_name,
                            "detail": f"Process '{name}' (PID: {pid}) sustained high CPU ({avg_cpu}% > {self.cpu_threshold}%) over {self.sustained_cycles} scan cycles.",
                        }
                    )
                    self.db.add_resource_sample(pid, name, cpu, mem)

            # Check high memory usage
            if mem >= self.mem_threshold:
                alerts.append(
                    {
                        "alert_type": "HIGH_MEMORY",
                        "severity": "LOW",
                        "pid": pid,
                        "process_name": name,
                        "exe_path": exe_path,
                        "parent_pid": ppid,
                        "parent_name": parent_name,
                        "detail": f"Process '{name}' (PID: {pid}) consuming excessive RAM ({mem} MB > {self.mem_threshold} MB).",
                    }
                )
                self.db.add_resource_sample(pid, name, cpu, mem)

        return alerts
