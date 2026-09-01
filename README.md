# ProcessGuard — Windows Service & Process Security Monitoring Agent

**ProcessGuard** is a real-time process and service security monitoring agent built in Python for Windows and cross-platform systems. It provides continuous security telemetry, baseline anomaly detection, automated alert dispatching, an interactive Rich live terminal dashboard, and dark-themed HTML report generation.

---

## 🚨 Problem Statement

In modern endpoint security, malicious software, rogue background scripts, and stealthy persistence mechanisms frequently exploit operating system mechanisms to evade detection:

- **Directory Evasion**: Malware binaries execute out of user-writable directories such as `AppData\Local\Temp`, `Downloads`, `Public`, or `/dev/shm` to bypass basic software policies.
- **Process Hollowing & Name Spoofing**: Malicious binaries disguise themselves with legitimate system names (e.g., spoofing `svchost.exe`) or run as hollowed processes with obscured executable paths.
- **Anomalous Parent-Child Executions**: Compromised applications (such as Office documents or web browsers) silently spawn shell interpreters (`cmd.exe`, `powershell.exe`, `wscript.exe`) to achieve remote execution.
- **Unauthorized Persistence**: Malware alters Windows `Run` / `RunOnce` registry keys or modifies system service binary paths to maintain persistence across system reboots.
- **Resource Hijacking**: Cryptominers and background encryption processes consume excessive system resources without raising standard system alarms.

---

## 🛡️ How ProcessGuard Solves It

ProcessGuard provides a lightweight, automated endpoint security monitoring agent that detects, logs, and alerts on these threats in real time:

1. **Automated Baseline Capture**: Establishes initial baselines for running processes, active services, and auto-start registry keys upon startup.
2. **Multi-Vector Detection Engine**: Operates 7 concurrent security monitoring modules:
   - **Process Baseline Monitor**: Tracks newly spawned processes and baseline process terminations.
   - **Service & Daemon Watcher**: Detects state changes, start type modifications, and service binary path tampering.
   - **Suspicious Path & Spoofing Detector**: Flags binaries in untrusted folders, hollowed processes, and filename mismatches.
   - **Resource Usage Analyzer**: Detects sustained high CPU spikes (>80%) and high RAM consumption (>500MB).
   - **Process Tree Anomaly Analyzer**: Flags illegal parent-child executions (e.g., Word or Chrome launching PowerShell).
   - **Binary Signature & Trust Checker**: Validates PE version resources and executable binary trust metadata.
   - **Registry Auto-Start Watcher**: Audits Windows auto-run registry keys for unauthorized modifications.
3. **Intelligent Alerting & Deduplication**: Manages alert cooldowns to prevent notification spam, logs events to a thread-safe SQLite database, and fires native desktop notifications for High/Critical threats.
4. **Interactive Dashboard & HTML Reporting**: Provides a real-time terminal UI for live monitoring alongside automated, dark-themed HTML telemetry exports containing actionable incident remediation steps.

---

## 🌟 Key Features

- **7 Modular Security Detectors**
- **Interactive Rich Live Terminal Dashboard**
- **Dark-Themed HTML Telemetry Exporter with CSS Charts**
- **In-Memory Cooldown & Native Desktop Notifications**

---

## ⚙️ Prerequisites & Installation

### Prerequisites
- **Python 3.9+** installed on Windows or Linux.

### Setup Instructions

1. **Navigate to Project Directory**:
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
