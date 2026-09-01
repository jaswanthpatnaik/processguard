"""MODULE 5 — Parent-Child Process Tree Anomaly Detector."""

from typing import Any, Dict, List
from utils.logger import get_logger

logger = get_logger()


class TreeAnalyzer:
    """Analyzes parent-child process tree relationships for suspicious execution chains."""

    def __init__(self, anomalous_pairs_cfg: List[Dict[str, str]]) -> None:
        self.rules: List[Dict[str, str]] = anomalous_pairs_cfg

    def scan(self, live_processes: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scans process tree relationships against configured anomaly rules."""
        alerts: List[Dict[str, Any]] = []

        for pid, p_info in live_processes.items():
            proc_name = p_info.get("name", "").lower()
            parent_name = p_info.get("parent_name", "").lower()
            ppid = p_info.get("ppid", 0)
            exe_path = p_info.get("exe_path", "")

            if not proc_name or not parent_name:
                continue

            for rule in self.rules:
                rule_parent = rule.get("parent", "").lower()
                rule_child = rule.get("child", "").lower()
                severity = rule.get("severity", "HIGH").upper()

                # Convert SUSPICIOUS severity string to HIGH for unified schema
                if severity == "SUSPICIOUS":
                    severity = "HIGH"

                parent_matches = rule_parent == "any" or rule_parent == parent_name
                child_matches = rule_child == proc_name

                if parent_matches and child_matches:
                    alerts.append(
                        {
                            "alert_type": "ANOMALOUS_PARENT_CHILD",
                            "severity": severity,
                            "pid": pid,
                            "process_name": p_info.get("name"),
                            "exe_path": exe_path,
                            "parent_pid": ppid,
                            "parent_name": p_info.get("parent_name"),
                            "detail": f"Anomalous process tree: Parent '{p_info.get('parent_name')}' (PID: {ppid}) spawned child '{p_info.get('name')}' (PID: {pid}).",
                        }
                    )
                    break

        return alerts
