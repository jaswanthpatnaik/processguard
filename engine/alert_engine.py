"""Alert Management Engine with severity classification, deduplication & desktop alerts."""

from datetime import datetime
import threading
from typing import Any, Dict, List, Optional, Tuple
from database.db_manager import DBManager
from utils.logger import get_logger
from utils.platform_check import safe_import

logger = get_logger()

# Safe import of plyer for cross-platform desktop notifications
plyer = safe_import("plyer")


class AlertEngine:
    """Processes, deduplicates, stores, and dispatches desktop notifications for security alerts."""

    def __init__(self, db: DBManager) -> None:
        self.db: DBManager = db
        self._lock: threading.Lock = threading.Lock()
        self.recent_alerts: List[Dict[str, Any]] = []
        # Cooldown map to prevent alert spam: (alert_type, pid, detail_hash) -> last_seen_timestamp
        self._cooldown_map: Dict[Tuple[str, int, str], float] = {}
        self.cooldown_seconds: float = 30.0

        # Pre-load existing alerts from DB
        self._reload_recent_alerts()

    def _reload_recent_alerts(self) -> None:
        """Loads existing alerts from SQLite into memory for dashboard views."""
        try:
            stored = self.db.get_alerts(limit=50)
            self.recent_alerts = stored
        except Exception as e:
            logger.error(f"Error loading initial alerts: {e}")

    def dispatch(self, alert_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Evaluates, deduplicates, stores in DB, and fires desktop notification for an alert."""
        alert_type = alert_data.get("alert_type", "UNKNOWN")
        severity = alert_data.get("severity", "LOW").upper()
        pid = alert_data.get("pid", 0)
        detail = alert_data.get("detail", "")
        now = datetime.now()

        # Deduplication check
        cooldown_key = (alert_type, pid, detail[:40])
        with self._lock:
            last_time = self._cooldown_map.get(cooldown_key, 0.0)
            if (now.timestamp() - last_time) < self.cooldown_seconds:
                return None  # Suppress duplicate alert within cooldown window
            self._cooldown_map[cooldown_key] = now.timestamp()

        # Construct full alert record
        record = {
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "alert_type": alert_type,
            "severity": severity,
            "pid": pid,
            "process_name": alert_data.get("process_name", "N/A"),
            "exe_path": alert_data.get("exe_path", ""),
            "parent_pid": alert_data.get("parent_pid", 0),
            "parent_name": alert_data.get("parent_name", "N/A"),
            "detail": detail,
            "resolved": 0,
        }

        # Persist to SQLite
        db_id = self.db.add_alert(record)
        record["id"] = db_id

        with self._lock:
            self.recent_alerts.insert(0, record)
            if len(self.recent_alerts) > 100:
                self.recent_alerts.pop()

        logger.warning(f"[{severity}] ALERT {alert_type}: {detail}")

        # Desktop notification via plyer
        if severity in ("CRITICAL", "HIGH"):
            self._send_desktop_notification(f"ProcessGuard [{severity}]", detail)

        return record

    def _send_desktop_notification(self, title: str, message: str) -> None:
        """Sends native desktop notification cleanly without crashing."""
        if plyer is None:
            return

        def _notify():
            try:
                # Silence plyer internal balloon_tip thread errors on Windows
                import threading as _th
                if hasattr(_th, "excepthook"):
                    _th.excepthook = lambda args: None

                plyer.notification.notify(
                    title=title,
                    message=message[:200],  # Truncate for display limits
                    app_name="ProcessGuard",
                    timeout=5,
                )
            except Exception:
                pass

        threading.Thread(target=_notify, daemon=True).start()

    def get_recent_alerts(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Returns list of most recent security alerts for UI dashboard."""
        with self._lock:
            return list(self.recent_alerts[:limit])

    def get_summary_counts(self) -> Dict[str, int]:
        """Returns counts of alerts grouped by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0}
        with self._lock:
            for a in self.recent_alerts:
                sev = a.get("severity", "LOW").upper()
                if sev in counts:
                    counts[sev] += 1
                counts["TOTAL"] += 1
        return counts
