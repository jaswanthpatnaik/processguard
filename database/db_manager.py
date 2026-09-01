"""SQLite Database Manager for ProcessGuard persistent storage."""

from datetime import datetime
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple
from utils.logger import get_logger

logger = get_logger()


class DBManager:
    """Thread-safe SQLite database manager for ProcessGuard."""

    def __init__(self, db_path: Path) -> None:
        self.db_path: Path = db_path
        self._lock: threading.Lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Creates a database connection with PRAGMA settings."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes SQLite tables if they do not exist."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS baseline_processes (
                        pid INTEGER PRIMARY KEY,
                        name TEXT,
                        exe_path TEXT,
                        cmdline TEXT,
                        ppid INTEGER,
                        parent_name TEXT,
                        username TEXT,
                        create_time REAL,
                        status TEXT,
                        captured_at TEXT
                    );
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        alert_type TEXT,
                        severity TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        exe_path TEXT,
                        parent_pid INTEGER,
                        parent_name TEXT,
                        detail TEXT,
                        resolved INTEGER DEFAULT 0
                    );
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS process_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        event_type TEXT,
                        pid INTEGER,
                        name TEXT,
                        exe_path TEXT,
                        username TEXT,
                        detail TEXT
                    );
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS service_baseline (
                        service_name TEXT PRIMARY KEY,
                        display_name TEXT,
                        status TEXT,
                        start_type TEXT,
                        binpath TEXT,
                        captured_at TEXT
                    );
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS resource_samples (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        cpu_percent REAL,
                        memory_mb REAL
                    );
                """)
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to initialize database tables: {e}")
            finally:
                conn.close()

    def save_process_baseline(self, processes: List[Dict[str, Any]]) -> None:
        """Overwrites baseline processes table with startup snapshot."""
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM baseline_processes;")
                for p in processes:
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO baseline_processes
                        (pid, name, exe_path, cmdline, ppid, parent_name, username, create_time, status, captured_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                        (
                            p.get("pid"),
                            p.get("name"),
                            p.get("exe_path"),
                            p.get("cmdline"),
                            p.get("ppid"),
                            p.get("parent_name"),
                            p.get("username"),
                            p.get("create_time"),
                            p.get("status"),
                            now,
                        ),
                    )
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Error saving process baseline: {e}")
            finally:
                conn.close()

    def get_process_baseline(self) -> Dict[int, Dict[str, Any]]:
        """Retrieves stored process baseline dictionary keyed by PID."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM baseline_processes;")
                rows = cursor.fetchall()
                return {dict(r)["pid"]: dict(r) for r in rows}
            except Exception as e:
                logger.error(f"Error reading process baseline: {e}")
                return {}
            finally:
                conn.close()

    def save_service_baseline(self, services: List[Dict[str, Any]]) -> None:
        """Overwrites service baseline table with current services."""
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM service_baseline;")
                for s in services:
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO service_baseline
                        (service_name, display_name, status, start_type, binpath, captured_at)
                        VALUES (?, ?, ?, ?, ?, ?);
                    """,
                        (
                            s.get("service_name"),
                            s.get("display_name"),
                            s.get("status"),
                            s.get("start_type"),
                            s.get("binpath"),
                            now,
                        ),
                    )
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Error saving service baseline: {e}")
            finally:
                conn.close()

    def get_service_baseline(self) -> Dict[str, Dict[str, Any]]:
        """Retrieves stored service baseline dictionary keyed by service_name."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM service_baseline;")
                rows = cursor.fetchall()
                return {dict(r)["service_name"]: dict(r) for r in rows}
            except Exception as e:
                logger.error(f"Error reading service baseline: {e}")
                return {}
            finally:
                conn.close()

    def add_alert(self, alert_data: Dict[str, Any]) -> int:
        """Inserts a new security alert into alerts table."""
        now = alert_data.get("timestamp") or datetime.now().isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO alerts
                    (timestamp, alert_type, severity, pid, process_name, exe_path, parent_pid, parent_name, detail, resolved)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0);
                """,
                    (
                        now,
                        alert_data.get("alert_type"),
                        alert_data.get("severity"),
                        alert_data.get("pid"),
                        alert_data.get("process_name"),
                        alert_data.get("exe_path"),
                        alert_data.get("parent_pid"),
                        alert_data.get("parent_name"),
                        alert_data.get("detail"),
                    ),
                )
                conn.commit()
                return cursor.lastrowid or 0
            except Exception as e:
                conn.rollback()
                logger.error(f"Error inserting alert: {e}")
                return 0
            finally:
                conn.close()

    def get_alerts(self, limit: int = 50, unresolved_only: bool = False) -> List[Dict[str, Any]]:
        """Retrieves recent security alerts ordered newest first."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                query = "SELECT * FROM alerts"
                if unresolved_only:
                    query += " WHERE resolved = 0"
                query += " ORDER BY id DESC LIMIT ?;"
                cursor.execute(query, (limit,))
                return [dict(r) for r in cursor.fetchall()]
            except Exception as e:
                logger.error(f"Error fetching alerts: {e}")
                return []
            finally:
                conn.close()

    def add_process_event(self, event_data: Dict[str, Any]) -> None:
        """Records a process launch or termination event."""
        now = event_data.get("timestamp") or datetime.now().isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO process_events (timestamp, event_type, pid, name, exe_path, username, detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                    (
                        now,
                        event_data.get("event_type"),
                        event_data.get("pid"),
                        event_data.get("name"),
                        event_data.get("exe_path"),
                        event_data.get("username"),
                        event_data.get("detail"),
                    ),
                )
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Error adding process event: {e}")
            finally:
                conn.close()

    def add_resource_sample(self, pid: int, proc_name: str, cpu: float, memory: float) -> None:
        """Records a high CPU or memory sample."""
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO resource_samples (timestamp, pid, process_name, cpu_percent, memory_mb)
                    VALUES (?, ?, ?, ?, ?);
                """,
                    (now, pid, proc_name, cpu, memory),
                )
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Error recording resource sample: {e}")
            finally:
                conn.close()
