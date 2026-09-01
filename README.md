# ProcessGuard — Windows Service & Process Security Monitoring Agent

**ProcessGuard** is a real-time process and service monitoring agent built in Python for Windows and cross-platform systems. It provides continuous security telemetry, anomaly detection, automated alert dispatching, an interactive Rich live terminal dashboard, and dark-themed HTML report generation.

---

## 🌟 Key Features

- **7 Modular Security Detectors**:
  1. **Process Snapshot Monitor**: Records process startup/termination baselines and tracks new executable spawns.
  2. **Service & Daemon Monitor**: Tracks state changes, start types, and binary path modifications for system services.
  3. **Suspicious Path & Spoofing Detector**: Flags binaries running out of `Temp`, `AppData`, `Downloads`, or `/dev/shm`, detects hollowed processes, and flags process name spoofing.
  4. **Resource Usage Monitor**: Tracks sustained CPU spikes (>80%) and memory consumption (>500MB).
  5. **Process Tree Anomaly Analyzer**: Detects suspicious parent-child process pairs (e.g., `winword.exe` spawning `powershell.exe` or `cmd.exe`).
  6. **Binary Signature & Trust Checker**: Validates Windows PE binary version resources and digital signature indicators.
  7. **Registry Auto-Start Watcher**: Monitors Windows `Run` and `RunOnce` registry keys for persistence changes.

- **Interactive Rich Terminal Dashboard**:
  - Live 4-panel dashboard showing active processes, alerts, monitored services, threat summary, system pulse, and module health.

- **Dark-Themed HTML Telemetry Exporter**:
  - Generates standalone, CSS-only charts and security recommendations for compliance and incident response.

- **Alert Engine & Notifications**:
  - In-memory alert deduplication with 30-second cooldown windows, SQLite database persistence, and native desktop notifications via `plyer`.

---

## 📁 Directory Structure

```text
processguard/
├── config.yaml               # Application configuration file
├── main.py                   # Entry point for ProcessGuard agent
├── requirements.txt          # Required Python packages
├── README.md                 # Project documentation
├── config/                   # Configuration loader module
├── dashboard/                # Rich live terminal dashboard UI
├── data/                     # SQLite database & system log storage
├── database/                 # SQLite DB manager with thread safety
├── engine/                   # Scan loop and alert dispatch engine
├── monitor/                  # 7 core security detection modules
├── reporter/                 # Dark-themed HTML exporter
└── utils/                    # Logger, platform checks, process helpers
```

---

## ⚙️ Prerequisites & Installation

### Prerequisites
- **Python 3.9+** installed on Windows or Linux.

### Setup Instructions

1. **Clone or Navigate to Project Directory**:
   ```powershell
   cd c:\Users\MSI\.gemini\antigravity\scratch\processguard
   ```

2. **Create a Virtual Environment**:
   ```powershell
   python -m venv venv
   ```

3. **Activate the Virtual Environment**:
   - **PowerShell**:
     ```powershell
     .\venv\Scripts\Activate.ps1
     ```
   - **Command Prompt (cmd)**:
     ```cmd
     .\venv\Scripts\activate.bat
     ```

4. **Install Dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

---

## 🚀 Running ProcessGuard

### 1. Run Live Interactive Terminal UI (Default)
Launches the full interactive Rich terminal UI dashboard:
```powershell
python main.py
```
*Or using the virtual environment directly:*
```powershell
.\venv\Scripts\python.exe main.py
```

### 2. Run in Headless Daemon Mode
Runs the background scan loop without rendering the terminal UI (suitable for background services/daemons):
```powershell
python main.py --no-ui
```

### 3. Generate HTML Security Telemetry Report
Exports a dark-themed HTML security report to `report.html` and exits (or periodically):
```powershell
python main.py --export-html report.html
```

### 4. Custom Configuration File
Specify a custom YAML configuration file:
```powershell
python main.py --config config.yaml
```

---

## ⌨️ Live Dashboard Controls

When running in Live Terminal UI mode (`python main.py`), use the following hotkeys:

| Key | Action |
|---|---|
| `1` | Switch to **Security Alerts Log** view |
| `2` | Switch to **Active Processes** view (Top 25 by CPU) |
| `3` | Switch to **Monitored Services & Daemons** view |
| `E` | Instantly **Export HTML Security Report** |
| `B` | **Rebuild Baselines** for processes, services, and registry |
| `←` / `→` | Cycle between dashboard views |
| `Q` | Safely **Quit** ProcessGuard |

---

## 📄 License
Internal Security Telemetry & Process Monitoring Tool.
