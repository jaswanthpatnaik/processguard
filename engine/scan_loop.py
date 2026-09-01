"""Daemon Scan Loop orchestrating all 7 ProcessGuard detection modules."""

import time
import threading
from typing import Any, Dict, List
import psutil
from config.loader import ConfigLoader
from database.db_manager import DBManager
from engine.alert_engine import AlertEngine
from monitor.path_detector import PathDetector
from monitor.process_snapshot import ProcessSnapshotMonitor
from monitor.registry_watcher import RegistryWatcher
from monitor.resource_monitor import ResourceMonitor
from monitor.service_monitor import ServiceMonitor
from monitor.signature_checker import SignatureChecker
from monitor.tree_analyzer import TreeAnalyzer
from utils.logger import get_logger

logger = get_logger()


class ScanLoop:
    """Orchestrates periodic scanning across all 7 monitoring modules."""

    def __init__(self, config: ConfigLoader, db: DBManager, alert_engine: AlertEngine) -> None:
        self.config: ConfigLoader = config
        self.db: DBManager = db
        self.alert_engine: AlertEngine = alert_engine

        # Initialize all 7 detection modules
        self.mod_snapshot = ProcessSnapshotMonitor(self.db)
        self.mod_service = ServiceMonitor(self.db)
        self.mod_path = PathDetector(self.config.suspicious_paths)
        self.mod_resource = ResourceMonitor(self.config.thresholds, self.db)
        self.mod_tree = TreeAnalyzer(self.config.anomalous_pairs)
        self.mod_signature = SignatureChecker(self.config.suspicious_paths.get("windows"))
        self.mod_registry = RegistryWatcher(self.config.registry_keys)

        self.running: bool = False
        self.scan_count: int = 0
        self.interval: int = self.config.scan_interval
        self._thread: threading.Thread = None

        # Module health status tracking
        self.module_health: Dict[str, bool] = {
            "1. Process Snapshot": True,
            "2. Service Monitor": True,
            "3. Suspicious Paths": True,
            "4. Resource Usage": True,
            "5. Process Tree": True,
            "6. Signature/Trust": self.mod_signature.available,
            "7. Registry Watch": self.mod_registry.available,
        }

        # System pulse data
        self.pulse_data: Dict[str, Any] = {
            "active_processes": 0,
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "disk_percent": 0.0,
            "top_flagged": [],
        }

    def rebuild_baseline(self) -> None:
        """Manually rebuilds startup process, service, and registry baselines."""
        logger.info("Rebuilding baseline snapshots for processes, services, and registry...")
        try:
            self.mod_snapshot.take_baseline()
            self.mod_service.take_baseline()
            if self.mod_registry.available:
                self.mod_registry.take_baseline()
            logger.info("Baseline rebuild completed successfully.")
        except Exception as e:
            logger.error(f"Error rebuilding baselines: {e}")

    def _execute_scan_cycle(self) -> None:
        """Executes a single scan cycle across all 7 monitoring modules."""
        self.scan_count += 1
        alerts_to_dispatch: List[Dict[str, Any]] = []

        # 1. Process Snapshot Scan
        new_procs: List[Dict[str, Any]] = []
        term_procs: List[Dict[str, Any]] = []
        live_procs: Dict[int, Dict[str, Any]] = {}
        try:
            new_procs, term_procs, live_procs = self.mod_snapshot.scan()
            self.module_health["1. Process Snapshot"] = True

            # Record events for new/terminated processes
            for np in new_procs:
                self.db.add_process_event(
                    {
                        "event_type": "NEW_PROCESS",
                        "pid": np.get("pid"),
                        "name": np.get("name"),
                        "exe_path": np.get("exe_path"),
                        "username": np.get("username"),
                        "detail": f"New process started: '{np.get('name')}' (PID: {np.get('pid')})",
                    }
                )
                # Dispatch INFO alert for normal new processes if not suspicious
                alerts_to_dispatch.append(
                    {
                        "alert_type": "NEW_PROCESS",
                        "severity": "INFO",
                        "pid": np.get("pid"),
                        "process_name": np.get("name"),
                        "exe_path": np.get("exe_path"),
                        "parent_pid": np.get("ppid"),
                        "parent_name": np.get("parent_name"),
                        "detail": f"New process spawned: '{np.get('name')}' (PID: {np.get('pid')}) by '{np.get('parent_name')}'",
                    }
                )

            for tp in term_procs:
                self.db.add_process_event(
                    {
                        "event_type": "TERMINATED",
                        "pid": tp.get("pid"),
                        "name": tp.get("name"),
                        "exe_path": tp.get("exe_path"),
                        "username": tp.get("username"),
                        "detail": f"Baseline process terminated: '{tp.get('name')}' (PID: {tp.get('pid')})",
                    }
                )
        except Exception as e:
            self.module_health["1. Process Snapshot"] = False
            logger.error(f"Module 1 (Process Snapshot) error: {e}")

        # Update System Pulse metrics
        try:
            self.pulse_data["active_processes"] = len(live_procs)
            self.pulse_data["cpu_percent"] = psutil.cpu_percent(interval=None)
            self.pulse_data["memory_percent"] = psutil.virtual_memory().percent
            self.pulse_data["disk_percent"] = psutil.disk_usage("/").percent
        except Exception:
            pass

        # 2. Service State Scan
        try:
            svc_alerts = self.mod_service.scan()
            alerts_to_dispatch.extend(svc_alerts)
            self.module_health["2. Service Monitor"] = True
        except Exception as e:
            self.module_health["2. Service Monitor"] = False
            logger.error(f"Module 2 (Service Monitor) error: {e}")

        # 3. Suspicious Path Scan
        try:
            path_alerts = self.mod_path.scan(live_procs)
            alerts_to_dispatch.extend(path_alerts)
            self.module_health["3. Suspicious Paths"] = True
        except Exception as e:
            self.module_health["3. Suspicious Paths"] = False
            logger.error(f"Module 3 (Path Detector) error: {e}")

        # 4. Resource Usage Scan
        try:
            resource_alerts = self.mod_resource.scan(live_procs)
            alerts_to_dispatch.extend(resource_alerts)
            self.module_health["4. Resource Usage"] = True
        except Exception as e:
            self.module_health["4. Resource Usage"] = False
            logger.error(f"Module 4 (Resource Monitor) error: {e}")

        # 5. Process Tree Anomaly Scan
        try:
            tree_alerts = self.mod_tree.scan(live_procs)
            alerts_to_dispatch.extend(tree_alerts)
            self.module_health["5. Process Tree"] = True
        except Exception as e:
            self.module_health["5. Process Tree"] = False
            logger.error(f"Module 5 (Tree Analyzer) error: {e}")

        # 6. Windows Signature / Version Resource Scan
        try:
            if self.mod_signature.available:
                sig_alerts = self.mod_signature.scan(new_procs)
                alerts_to_dispatch.extend(sig_alerts)
                self.module_health["6. Signature/Trust"] = True
        except Exception as e:
            self.module_health["6. Signature/Trust"] = False
            logger.error(f"Module 6 (Signature Checker) error: {e}")

        # 7. Registry Run Key Scan
        try:
            if self.mod_registry.available:
                reg_alerts = self.mod_registry.scan()
                alerts_to_dispatch.extend(reg_alerts)
                self.module_health["7. Registry Watch"] = True
        except Exception as e:
            self.module_health["7. Registry Watch"] = False
            logger.error(f"Module 7 (Registry Watcher) error: {e}")

        # Dispatch all alerts to AlertEngine
        for alert_item in alerts_to_dispatch:
            self.alert_engine.dispatch(alert_item)

    def _loop(self) -> None:
        """Main loop executed inside background thread."""
        logger.info(f"Scan loop background thread started (Interval: {self.interval}s).")
        while self.running:
            start_time = time.time()
            try:
                self._execute_scan_cycle()
            except Exception as e:
                logger.error(f"Unhandled error in scan cycle: {e}")

            elapsed = time.time() - start_time
            sleep_time = max(0.1, self.interval - elapsed)
            time.sleep(sleep_time)

    def start(self) -> None:
        """Starts the background scan loop thread."""
        if not self.running:
            self.running = True
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stops the background scan loop thread cleanly."""
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Scan loop background thread stopped.")
