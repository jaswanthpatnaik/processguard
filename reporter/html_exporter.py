"""HTML Security Report Exporter for ProcessGuard with dark theme & CSS-only charts."""

from datetime import datetime
from pathlib import Path
import platform
import socket
from typing import Any, Dict, List
from database.db_manager import DBManager
from utils.logger import get_logger

logger = get_logger()


class HTMLExporter:
    """Exports comprehensive dark-themed HTML security monitoring reports."""

    def __init__(self, db: DBManager) -> None:
        self.db: DBManager = db

    def generate_report(self, output_file: str = "report.html") -> Path:
        """Generates and writes standalone HTML security report to disk."""
        out_path = Path(output_file).resolve()

        alerts = self.db.get_alerts(limit=100)
        baseline_procs = self.db.get_process_baseline()
        baseline_svcs = self.db.get_service_baseline()

        # Calculate summary metrics
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for a in alerts:
            sev = a.get("severity", "LOW").upper()
            if sev in counts:
                counts[sev] += 1

        total_alerts = len(alerts)
        critical_high = counts["CRITICAL"] + counts["HIGH"]

        # Top processes by CPU for CSS bar chart
        proc_list = list(baseline_procs.values())
        proc_list.sort(key=lambda x: x.get("cpu_percent", 0.0), reverse=True)
        top_cpu_procs = proc_list[:10]

        # Filter process anomalies, service changes, registry changes
        proc_anomalies = [a for a in alerts if a.get("alert_type") in ("SUSPICIOUS_PATH", "ANOMALOUS_PARENT_CHILD", "HIGH_CPU", "HIGH_MEMORY", "UNSIGNED_EXECUTABLE", "SUSPICIOUS_UNSIGNED")]
        svc_changes = [a for a in alerts if "SERVICE" in a.get("alert_type", "")]
        reg_changes = [a for a in alerts if "REGISTRY" in a.get("alert_type", "")]

        # Generate automated recommendations based on alerts
        recommendations = self._generate_recommendations(alerts)

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hostname = socket.gethostname()

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ProcessGuard Security Telemetry Report</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b2d;
            --header-bg: #1a1f2e;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --border-color: #30363d;
            --accent-blue: #58a6ff;
            --sev-critical: #ff4d4d;
            --sev-high: #ff944d;
            --sev-medium: #ffd633;
            --sev-low: #8c8c8c;
            --sev-info: #58a6ff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%);
            padding: 24px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
            color: #ffffff;
        }}
        .header .meta {{
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 6px;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            display: inline-block;
        }}
        .badge-critical {{ background: rgba(255, 77, 77, 0.2); color: var(--sev-critical); border: 1px solid var(--sev-critical); }}
        .badge-high {{ background: rgba(255, 148, 77, 0.2); color: var(--sev-high); border: 1px solid var(--sev-high); }}
        .badge-medium {{ background: rgba(255, 214, 51, 0.2); color: var(--sev-medium); border: 1px solid var(--sev-medium); }}
        .badge-low {{ background: rgba(140, 140, 140, 0.2); color: var(--sev-low); border: 1px solid var(--sev-low); }}
        .badge-info {{ background: rgba(88, 166, 255, 0.2); color: var(--sev-info); border: 1px solid var(--sev-info); }}

        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background-color: var(--card-bg);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
        }}
        .card .title {{
            font-size: 13px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #ffffff;
            margin-top: 8px;
        }}

        .section {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .section h2 {{
            margin-top: 0;
            font-size: 18px;
            color: #ffffff;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 13px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: var(--header-bg);
            color: var(--text-muted);
            font-weight: 600;
        }}
        tr:hover {{
            background-color: rgba(255, 255, 255, 0.03);
        }}

        /* Pure CSS Bar Chart */
        .chart-container {{
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-top: 16px;
        }}
        .chart-row {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .chart-label {{
            width: 180px;
            font-size: 13px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .chart-bar-bg {{
            flex: 1;
            background-color: var(--header-bg);
            border-radius: 4px;
            height: 20px;
            overflow: hidden;
        }}
        .chart-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, #58a6ff 0%, #ff4d4d 100%);
            border-radius: 4px;
            transition: width 0.3s ease;
        }}
        .chart-val {{
            width: 50px;
            font-size: 13px;
            text-align: right;
            font-weight: bold;
        }}

        .rec-list {{
            list-style: none;
            padding-left: 0;
        }}
        .rec-item {{
            background-color: var(--header-bg);
            border-left: 4px solid var(--accent-blue);
            padding: 12px 16px;
            margin-bottom: 10px;
            border-radius: 0 6px 6px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div>
                <h1>ProcessGuard Monitoring Report</h1>
                <div class="meta">Host: {hostname} | OS: {platform.system()} {platform.release()} | Generated: {now_str}</div>
            </div>
            <div>
                <span class="badge badge-info">Status: Active</span>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="cards-grid">
            <div class="card">
                <div class="title">Total Alerts</div>
                <div class="value">{total_alerts}</div>
            </div>
            <div class="card">
                <div class="title">Critical / High</div>
                <div class="value" style="color: var(--sev-critical);">{critical_high}</div>
            </div>
            <div class="card">
                <div class="title">Baseline Processes</div>
                <div class="value">{len(baseline_procs)}</div>
            </div>
            <div class="card">
                <div class="title">Monitored Services</div>
                <div class="value">{len(baseline_svcs)}</div>
            </div>
        </div>

        <!-- Alert Timeline -->
        <div class="section">
            <h2>Recent Security Alert Log</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Severity</th>
                        <th>Alert Type</th>
                        <th>PID</th>
                        <th>Process Name</th>
                        <th>Detail</th>
                    </tr>
                </thead>
                <tbody>
"""

        if not alerts:
            html_content += "<tr><td colspan='6' style='text-align:center; color: var(--text-muted);'>No alerts recorded. System clean.</td></tr>"
        else:
            for a in alerts[:30]:
                sev = a.get("severity", "LOW").upper()
                badge_cls = f"badge-{sev.lower()}"
                html_content += f"""
                    <tr>
                        <td>{a.get('timestamp', '')}</td>
                        <td><span class="badge {badge_cls}">{sev}</span></td>
                        <td>{a.get('alert_type', '')}</td>
                        <td>{a.get('pid', 0)}</td>
                        <td><strong>{a.get('process_name', 'N/A')}</strong></td>
                        <td>{a.get('detail', '')}</td>
                    </tr>
                """

        html_content += """
                </tbody>
            </table>
        </div>

        <!-- CSS CPU Bar Chart -->
        <div class="section">
            <h2>Top Processes by CPU Consumption</h2>
            <div class="chart-container">
"""

        max_cpu = max([p.get("cpu_percent", 0.1) for p in top_cpu_procs] + [100.0])
        for p in top_cpu_procs:
            cpu_val = p.get("cpu_percent", 0.0)
            bar_width = min(100, max(2, (cpu_val / max_cpu) * 100))
            p_name = p.get("name", "Unknown")
            html_content += f"""
                <div class="chart-row">
                    <div class="chart-label">{p_name} (PID: {p.get('pid')})</div>
                    <div class="chart-bar-bg">
                        <div class="chart-bar-fill" style="width: {bar_width:.1f}%;"></div>
                    </div>
                    <div class="chart-val">{cpu_val:.1f}%</div>
                </div>
            """

        html_content += """
            </div>
        </div>

        <!-- Process Anomalies -->
        <div class="section">
            <h2>Process Path & Tree Anomalies</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Process</th>
                        <th>Executable Path</th>
                        <th>Detail</th>
                    </tr>
                </thead>
                <tbody>
"""

        if not proc_anomalies:
            html_content += "<tr><td colspan='5' style='text-align:center; color: var(--text-muted);'>No process path or tree anomalies detected.</td></tr>"
        else:
            for pa in proc_anomalies[:15]:
                sev = pa.get("severity", "LOW").upper()
                badge_cls = f"badge-{sev.lower()}"
                html_content += f"""
                    <tr>
                        <td>{pa.get('alert_type')}</td>
                        <td><span class="badge {badge_cls}">{sev}</span></td>
                        <td>{pa.get('process_name')} (PID: {pa.get('pid')})</td>
                        <td><code>{pa.get('exe_path', 'N/A')}</code></td>
                        <td>{pa.get('detail')}</td>
                    </tr>
                """

        html_content += """
                </tbody>
            </table>
        </div>

        <!-- Service Changes -->
        <div class="section">
            <h2>Service & Daemon Telemetry Changes</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Service Name</th>
                        <th>Detail</th>
                    </tr>
                </thead>
                <tbody>
"""

        if not svc_changes:
            html_content += "<tr><td colspan='4' style='text-align:center; color: var(--text-muted);'>No service state or binary path modifications recorded.</td></tr>"
        else:
            for sc in svc_changes[:15]:
                sev = sc.get("severity", "LOW").upper()
                badge_cls = f"badge-{sev.lower()}"
                html_content += f"""
                    <tr>
                        <td>{sc.get('alert_type')}</td>
                        <td><span class="badge {badge_cls}">{sev}</span></td>
                        <td>{sc.get('service_name', 'N/A')}</td>
                        <td>{sc.get('detail')}</td>
                    </tr>
                """

        html_content += """
                </tbody>
            </table>
        </div>

        <!-- Registry Persistence Changes -->
        <div class="section">
            <h2>Windows Registry Persistence Changes</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Detail</th>
                    </tr>
                </thead>
                <tbody>
"""

        if not reg_changes:
            html_content += "<tr><td colspan='3' style='text-align:center; color: var(--text-muted);'>No registry auto-start persistence modifications detected.</td></tr>"
        else:
            for rc in reg_changes[:15]:
                sev = rc.get("severity", "LOW").upper()
                badge_cls = f"badge-{sev.lower()}"
                html_content += f"""
                    <tr>
                        <td>{rc.get('alert_type')}</td>
                        <td><span class="badge {badge_cls}">{sev}</span></td>
                        <td>{rc.get('detail')}</td>
                    </tr>
                """

        html_content += """
                </tbody>
            </table>
        </div>

        <!-- Recommendations -->
        <div class="section">
            <h2>Security Incident Recommendations</h2>
            <ul class="rec-list">
"""

        for rec in recommendations:
            html_content += f'<li class="rec-item">{rec}</li>'

        html_content += """
            </ul>
        </div>
    </div>
</body>
</html>
"""

        out_path.write_text(html_content, encoding="utf-8")
        logger.info(f"Generated dark-themed HTML report at: {out_path}")
        return out_path

    def _generate_recommendations(self, alerts: List[Dict[str, Any]]) -> List[str]:
        """Generates context-aware security remediation recommendations based on alert findings."""
        recs: List[str] = []

        alert_types = {a.get("alert_type") for a in alerts}

        if "SUSPICIOUS_PATH" in alert_types:
            recs.append("<strong>Executable Path Hardening:</strong> Investigate binaries executing out of <code>Temp</code>, <code>AppData</code>, or <code>/dev/shm</code>. Consider enforcing AppLocker / Software Restriction Policies.")

        if "ANOMALOUS_PARENT_CHILD" in alert_types:
            recs.append("<strong>Script & Command Execution Controls:</strong> Office documents or web browsers spawned shell processes (`cmd.exe` / `powershell.exe`). Restrict macro execution in Microsoft Office and enable Attack Surface Reduction (ASR) rules.")

        if "REGISTRY_PERSISTENCE" in alert_types or "REGISTRY_MODIFIED" in alert_types:
            recs.append("<strong>Persistence Cleanup:</strong> New autorun entries were added to Registry Run keys. Perform an Autoruns scan and remove unauthorized registry entries.")

        if "SERVICE_PATH_CHANGED" in alert_types or "NEW_SERVICE" in alert_types:
            recs.append("<strong>Service Audit:</strong> A Windows service binary path was modified or a new service was installed. Verify service binary signatures and administrative rights.")

        if "HIGH_CPU" in alert_types:
            recs.append("<strong>Resource Abuse Analysis:</strong> Processes exhibited sustained high CPU usage. Inspect for unauthorized cryptomining or background encryption activity.")

        if not recs:
            recs.append("<strong>Baseline Maintenance:</strong> System is operating within expected baseline thresholds. Continue periodic scanning and update baseline upon administrative software deployment.")

        return recs
