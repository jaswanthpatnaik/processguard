"""MODULE 1 — Process Baseline Snapshot & Lifecycle Monitor."""

from typing import Any, Dict, List, Tuple
import psutil
from database.db_manager import DBManager
from utils.logger import get_logger
from utils.process_helpers import safe_getattr

logger = get_logger()


class ProcessSnapshotMonitor:
    """Captures startup process baseline and monitors live process creation/termination."""

    def __init__(self, db: DBManager) -> None:
        self.db: DBManager = db
        self.baseline: Dict[int, Dict[str, Any]] = {}
        self.take_baseline()

    def get_live_processes(self) -> Dict[int, Dict[str, Any]]:
        """Enumerate all running processes safely."""
        live: Dict[int, Dict[str, Any]] = {}
        for proc in psutil.process_iter(attrs=None):
            try:
                pid = proc.pid
                p_info = {
                    "pid": pid,
                    "name": safe_getattr(proc, "name", "Unknown"),
                    "exe_path": safe_getattr(proc, "exe", ""),
                    "cmdline": safe_getattr(proc, "cmdline", ""),
                    "ppid": safe_getattr(proc, "ppid", 0),
                    "parent_name": safe_getattr(proc, "parent_name", "N/A"),
                    "username": safe_getattr(proc, "username", "N/A"),
                    "create_time": safe_getattr(proc, "create_time", 0.0),
                    "status": safe_getattr(proc, "status", "unknown"),
                    "cpu_percent": safe_getattr(proc, "cpu_percent", 0.0),
                    "memory_mb": safe_getattr(proc, "memory_mb", 0.0),
                }
                live[pid] = p_info
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"Error reading process {getattr(proc, 'pid', 'unknown')}: {e}")
        return live

    def take_baseline(self) -> Dict[int, Dict[str, Any]]:
        """Captures initial baseline snapshot and persists to SQLite."""
        self.baseline = self.get_live_processes()
        self.db.save_process_baseline(list(self.baseline.values()))
        logger.info(f"Captured process baseline: {len(self.baseline)} active processes recorded.")
        return self.baseline

    def scan(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[int, Dict[str, Any]]]:
        """Compares current running processes against baseline.

        Returns:
            Tuple of (new_processes, terminated_processes, live_processes_dict)
        """
        live_processes = self.get_live_processes()
        new_processes: List[Dict[str, Any]] = []
        terminated_processes: List[Dict[str, Any]] = []

        # Find new processes not in baseline
        for pid, p_info in live_processes.items():
            if pid not in self.baseline:
                new_processes.append(p_info)

        # Find processes in baseline that are no longer running
        for pid, p_info in self.baseline.items():
            if pid not in live_processes:
                terminated_processes.append(p_info)

        return new_processes, terminated_processes, live_processes
