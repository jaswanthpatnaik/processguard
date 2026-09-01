"""MODULE 7 — Windows Registry Run & Auto-Start Persistence Watcher."""

from typing import Any, Dict, List, Tuple
from utils.logger import get_logger
from utils.platform_check import is_windows

logger = get_logger()

# Safe stdlib winreg import
if is_windows():
    import winreg
else:
    winreg = None


class RegistryWatcher:
    """Monitors Windows Auto-Start Extensibility Points (ASEPs) for persistence additions or modifications."""

    def __init__(self, key_paths: List[str]) -> None:
        self.available: bool = is_windows() and winreg is not None
        self.target_keys: List[str] = key_paths
        self.baseline: Dict[str, Dict[str, str]] = {}
        if self.available:
            self.take_baseline()
        else:
            logger.debug("RegistryWatcher: Non-Windows OS detected — skipping registry monitoring.")

    def _read_key_values(self, hive: int, subkey_path: str) -> Dict[str, str]:
        """Reads all name-value pairs from a registry subkey."""
        values: Dict[str, str] = {}
        if not self.available:
            return values

        try:
            key = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ)
            index = 0
            while True:
                try:
                    val_name, val_data, _ = winreg.EnumValue(key, index)
                    values[val_name] = str(val_data)
                    index += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

        return values

    def _get_all_registry_values(self) -> Dict[str, Dict[str, str]]:
        """Reads current state of all configured registry keys across HKCU and HKLM."""
        state: Dict[str, Dict[str, str]] = {}
        if not self.available:
            return state

        hives = [
            ("HKCU", winreg.HKEY_CURRENT_USER),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE),
        ]

        for hive_name, hive_handle in hives:
            for key_path in self.target_keys:
                full_key_id = f"{hive_name}\\{key_path}"
                state[full_key_id] = self._read_key_values(hive_handle, key_path)

        return state

    def take_baseline(self) -> Dict[str, Dict[str, str]]:
        """Takes initial snapshot of startup registry entries."""
        if not self.available:
            return {}
        self.baseline = self._get_all_registry_values()
        total_entries = sum(len(v) for v in self.baseline.values())
        logger.info(f"Captured registry baseline: {total_entries} persistence entries recorded.")
        return self.baseline

    def scan(self) -> List[Dict[str, Any]]:
        """Scans registry keys for persistence modifications, additions, or deletions."""
        if not self.available:
            return []

        live_state = self._get_all_registry_values()
        alerts: List[Dict[str, Any]] = []

        for key_id, live_vals in live_state.items():
            base_vals = self.baseline.get(key_id, {})

            # Check for new or modified values
            for val_name, val_data in live_vals.items():
                if val_name not in base_vals:
                    alerts.append(
                        {
                            "alert_type": "REGISTRY_PERSISTENCE",
                            "severity": "HIGH",
                            "pid": 0,
                            "process_name": "System Registry",
                            "exe_path": val_data,
                            "parent_pid": 0,
                            "parent_name": "N/A",
                            "detail": f"New persistence autorun entry added under [{key_id}]: '{val_name}' = '{val_data}'",
                        }
                    )
                elif base_vals[val_name] != val_data:
                    alerts.append(
                        {
                            "alert_type": "REGISTRY_MODIFIED",
                            "severity": "MEDIUM",
                            "pid": 0,
                            "process_name": "System Registry",
                            "exe_path": val_data,
                            "parent_pid": 0,
                            "parent_name": "N/A",
                            "detail": f"Persistence autorun entry modified under [{key_id}]: '{val_name}' changed to '{val_data}'",
                        }
                    )

            # Check for deleted values
            for val_name, val_data in base_vals.items():
                if val_name not in live_vals:
                    alerts.append(
                        {
                            "alert_type": "REGISTRY_DELETED",
                            "severity": "LOW",
                            "pid": 0,
                            "process_name": "System Registry",
                            "exe_path": val_data,
                            "parent_pid": 0,
                            "parent_name": "N/A",
                            "detail": f"Persistence autorun entry deleted from [{key_id}]: '{val_name}'",
                        }
                    )

        # Update baseline after scan
        self.baseline = live_state
        return alerts
