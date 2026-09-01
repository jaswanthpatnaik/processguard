"""MODULE 2 — Service State & Linux Daemon Monitor."""

import subprocess
from typing import Any, Dict, List, Tuple
import psutil
from database.db_manager import DBManager
from utils.logger import get_logger
from utils.platform_check import is_linux, is_windows

logger = get_logger()


class ServiceMonitor:
    """Monitors Windows services or Linux systemctl daemons for status/binary changes."""

    def __init__(self, db: DBManager) -> None:
        self.db: DBManager = db
        self.baseline: Dict[str, Dict[str, Any]] = {}
        self.take_baseline()

    def get_live_services(self) -> Dict[str, Dict[str, Any]]:
        """Enumerates active services / daemons across Windows and Linux."""
        services: Dict[str, Dict[str, Any]] = {}

        if is_windows():
            try:
                for s in psutil.win_service_iter():
                    try:
                        info = s.as_dict()
                        s_name = info.get("name", "")
                        if not s_name:
                            continue
                        services[s_name] = {
                            "service_name": s_name,
                            "display_name": info.get("display_name", s_name),
                            "status": info.get("status", "unknown"),
                            "start_type": info.get("start_type", "unknown"),
                            "binpath": info.get("binpath", ""),
                            "pid": info.get("pid", None),
                        }
                    except Exception:
                        continue
            except Exception as e:
                logger.error(f"Error iterating Windows services: {e}")

        elif is_linux():
            try:
                # Fallback via systemctl
                cmd = ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                for line in output.strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        s_name = parts[0]
                        load_state = parts[1]
                        active_state = parts[2]
                        sub_state = parts[3]
                        services[s_name] = {
                            "service_name": s_name,
                            "display_name": s_name,
                            "status": f"{active_state}/{sub_state}",
                            "start_type": load_state,
                            "binpath": f"/etc/systemd/system/{s_name}",
                            "pid": None,
                        }
            except Exception as e:
                logger.debug(f"Error parsing systemctl services: {e}")

        return services

    def take_baseline(self) -> Dict[str, Dict[str, Any]]:
        """Takes startup service baseline snapshot."""
        self.baseline = self.get_live_services()
        self.db.save_service_baseline(list(self.baseline.values()))
        logger.info(f"Captured service baseline: {len(self.baseline)} services/daemons recorded.")
        return self.baseline

    def scan(self) -> List[Dict[str, Any]]:
        """Scans live services against baseline to detect state or binary path anomalies."""
        live_services = self.get_live_services()
        alerts: List[Dict[str, Any]] = []

        # Check for new services or changed properties
        for s_name, live_info in live_services.items():
            if s_name not in self.baseline:
                alerts.append(
                    {
                        "alert_type": "NEW_SERVICE",
                        "severity": "MEDIUM",
                        "service_name": s_name,
                        "detail": f"New service registered: '{live_info.get('display_name')}' (BinPath: {live_info.get('binpath')})",
                        "binpath": live_info.get("binpath"),
                    }
                )
            else:
                base_info = self.baseline[s_name]
                # Check for binary path changes
                if base_info.get("binpath") and live_info.get("binpath") and base_info["binpath"] != live_info["binpath"]:
                    alerts.append(
                        {
                            "alert_type": "SERVICE_PATH_CHANGED",
                            "severity": "HIGH",
                            "service_name": s_name,
                            "detail": f"Service binary path modified from '{base_info.get('binpath')}' to '{live_info.get('binpath')}'",
                            "binpath": live_info.get("binpath"),
                        }
                    )
                # Check for unexpected service stoppage
                if base_info.get("status") == "running" and live_info.get("status") in ("stopped", "stop_pending"):
                    alerts.append(
                        {
                            "alert_type": "SERVICE_STOPPED",
                            "severity": "MEDIUM",
                            "service_name": s_name,
                            "detail": f"Service '{s_name}' changed state from RUNNING to {live_info.get('status').upper()}",
                            "binpath": live_info.get("binpath"),
                        }
                    )

        return alerts
