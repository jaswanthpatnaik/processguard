"""Configuration loader for ProcessGuard using PyYAML with safe defaults."""

import os
from pathlib import Path
from typing import Any, Dict, List
import yaml

DEFAULT_CONFIG: Dict[str, Any] = {
    "scan_interval_seconds": 5,
    "db_path": "data/processguard.db",
    "thresholds": {
        "cpu_alert_percent": 80,
        "memory_alert_mb": 500,
        "cpu_sustained_cycles": 3,
    },
    "suspicious_paths": {
        "windows": [
            "\\Temp\\",
            "\\AppData\\Local\\Temp\\",
            "\\Downloads\\",
            "\\AppData\\Roaming\\",
            "\\Public\\",
            "\\ProgramData\\",
        ],
        "linux": [
            "/tmp/",
            "/var/tmp/",
            "/dev/shm/",
        ],
    },
    "anomalous_pairs": [
        {"parent": "winword.exe", "child": "cmd.exe", "severity": "CRITICAL"},
        {"parent": "winword.exe", "child": "powershell.exe", "severity": "CRITICAL"},
        {"parent": "excel.exe", "child": "cmd.exe", "severity": "CRITICAL"},
        {"parent": "excel.exe", "child": "powershell.exe", "severity": "CRITICAL"},
        {"parent": "explorer.exe", "child": "cmd.exe", "severity": "SUSPICIOUS"},
        {"parent": "chrome.exe", "child": "cmd.exe", "severity": "CRITICAL"},
        {"parent": "firefox.exe", "child": "powershell.exe", "severity": "CRITICAL"},
        {"parent": "cmd.exe", "child": "powershell.exe", "severity": "SUSPICIOUS"},
        {"parent": "any", "child": "wscript.exe", "severity": "HIGH"},
        {"parent": "any", "child": "cscript.exe", "severity": "HIGH"},
    ],
    "registry_keys": [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ],
}


class ConfigLoader:
    """Loads and validates configuration from YAML or returns defaults."""

    def __init__(self, config_path: str = "config.yaml") -> None:
        self.project_root: Path = Path(__file__).resolve().parent.parent
        self.config_path: Path = self.project_root / config_path
        self._config: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        """Loads YAML file or falls back to DEFAULT_CONFIG."""
        if not self.config_path.exists():
            return DEFAULT_CONFIG.copy()

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    # Merge with default config to ensure missing keys have fallbacks
                    merged = DEFAULT_CONFIG.copy()
                    merged.update(data)
                    return merged
        except Exception:
            pass

        return DEFAULT_CONFIG.copy()

    @property
    def config(self) -> Dict[str, Any]:
        """Returns the loaded config dictionary."""
        return self._config

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a configuration value by key."""
        return self._config.get(key, default)

    @property
    def db_abs_path(self) -> Path:
        """Returns absolute path to SQLite database."""
        relative_db = self.get("db_path", "data/processguard.db")
        return self.project_root / relative_db

    @property
    def scan_interval(self) -> int:
        """Returns scan interval in seconds."""
        return int(self.get("scan_interval_seconds", 5))

    @property
    def thresholds(self) -> Dict[str, int]:
        """Returns resource alert thresholds."""
        return self.get("thresholds", DEFAULT_CONFIG["thresholds"])

    @property
    def suspicious_paths(self) -> Dict[str, List[str]]:
        """Returns platform suspicious paths."""
        return self.get("suspicious_paths", DEFAULT_CONFIG["suspicious_paths"])

    @property
    def anomalous_pairs(self) -> List[Dict[str, str]]:
        """Returns list of anomalous parent-child pairs."""
        return self.get("anomalous_pairs", DEFAULT_CONFIG["anomalous_pairs"])

    @property
    def registry_keys(self) -> List[str]:
        """Returns list of target registry keys."""
        return self.get("registry_keys", DEFAULT_CONFIG["registry_keys"])


def load_config(config_path: str = "config.yaml") -> ConfigLoader:
    """Helper function to instantiate ConfigLoader."""
    return ConfigLoader(config_path)
