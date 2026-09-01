"""Rich Live Terminal Dashboard for ProcessGuard real-time telemetry."""

import os
import platform
import socket
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
import psutil

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

from engine.alert_engine import AlertEngine
from engine.scan_loop import ScanLoop
from utils.platform_check import is_windows

# Start time tracking for uptime calculation
START_TIME = datetime.now()


class TerminalDashboard:
    """Rich interactive live terminal dashboard displaying security telemetry."""

    def __init__(self, scan_loop: ScanLoop, alert_engine: AlertEngine) -> None:
        self.scan_loop: ScanLoop = scan_loop
        self.alert_engine: AlertEngine = alert_engine
        self.console: Console = Console()
        self.active_view: int = 1  # 1: Alerts, 2: Processes, 3: Services
        self.status_message: str = ""
        self.status_clear_time: float = 0.0
        self._listener_thread: Optional[threading.Thread] = None

    def _get_uptime_str(self) -> str:
        """Calculates formatted application uptime string."""
        delta = datetime.now() - START_TIME
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}h:{minutes:02d}m:{seconds:02d}s"

    def render_header(self) -> Panel:
        """Renders header panel with platform telemetry and scan metrics."""
        hostname = socket.gethostname()
        try:
            username = os.getlogin()
        except Exception:
            username = "SystemUser"

        uptime = self._get_uptime_str()
        scan_cnt = self.scan_loop.scan_count

        base_proc_cnt = len(self.scan_loop.mod_snapshot.baseline)
        base_svc_cnt = len(self.scan_loop.mod_service.baseline)
        reg_cnt = len(self.scan_loop.config.registry_keys) if is_windows() else 0

        header_text = Text()
        header_text.append("ProcessGuard v1.0 — Windows Service & Process Monitoring Agent\n", style="bold white on dark_blue")
        header_text.append(
            f"OS: {platform.system()} {platform.release()}  |  Host: {hostname}  |  User: {username}  |  Uptime: {uptime}  |  Scans: {scan_cnt}\n",
            style="cyan",
        )
        header_text.append(
            f"Baselines: {base_proc_cnt} Processes  |  {base_svc_cnt} Services  |  {reg_cnt} Registry Run Keys Monitored",
            style="bold yellow",
        )

        return Panel(header_text, box=box.DOUBLE_EDGE, style="bright_white on black")

    def render_left_panel(self) -> Panel:
        """Renders active view in left panel (1: Alerts, 2: Processes, 3: Services)."""
        if self.active_view == 1:
            return self._render_alerts_table()
        elif self.active_view == 2:
            return self._render_processes_table()
        else:
            return self._render_services_table()

    def _render_alerts_table(self) -> Panel:
        """View 1: Last 30 alerts table."""
        alerts = self.alert_engine.get_recent_alerts(limit=30)
        table = Table(expand=True, box=box.SIMPLE_HEAVY, show_header=True, header_style="bold magenta")
        table.add_column("Time", style="dim", width=19)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=22)
        table.add_column("PID", justify="right", width=6)
        table.add_column("Process", width=16)
        table.add_column("Detail", style="italic")

        for a in alerts:
            sev = a.get("severity", "LOW").upper()
            if sev == "CRITICAL":
                sev_style = "bold bright_red"
            elif sev == "HIGH":
                sev_style = "red"
            elif sev == "MEDIUM":
                sev_style = "yellow"
            elif sev == "LOW":
                sev_style = "dim"
            else:
                sev_style = "dim white"

            table.add_row(
                a.get("timestamp", "")[-8:],
                Text(sev, style=sev_style),
                a.get("alert_type", ""),
                str(a.get("pid", 0)),
                str(a.get("process_name", "N/A"))[:15],
                str(a.get("detail", "")),
            )

        return Panel(table, title="[1] Security Alerts Log (Newest First)", border_style="magenta")

    def _render_processes_table(self) -> Panel:
        """View 2: Top 25 live processes sorted by CPU %."""
        procs = list(self.scan_loop.mod_snapshot.get_live_processes().values())
        procs.sort(key=lambda x: x.get("cpu_percent", 0.0), reverse=True)
        top_25 = procs[:25]

        table = Table(expand=True, box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
        table.add_column("PID", justify="right", width=6)
        table.add_column("Name", width=18)
        table.add_column("CPU%", justify="right", width=8)
        table.add_column("RAM(MB)", justify="right", width=10)
        table.add_column("Status", width=10)
        table.add_column("User", width=14)
        table.add_column("Executable Path")

        for p in top_25:
            cpu = p.get("cpu_percent", 0.0)
            cpu_style = "bold red" if cpu > 80 else ("yellow" if cpu > 30 else "green")
            mem = p.get("memory_mb", 0.0)
            mem_style = "bold red" if mem > 500 else "white"

            table.add_row(
                str(p.get("pid")),
                p.get("name", "Unknown")[:17],
                Text(f"{cpu:.1f}%", style=cpu_style),
                Text(f"{mem:.1f}", style=mem_style),
                p.get("status", "unknown"),
                str(p.get("username", "N/A"))[:13],
                str(p.get("exe_path", ""))[:45],
            )

        return Panel(table, title="[2] Active Processes (Top 25 by CPU Usage)", border_style="cyan")

    def _render_services_table(self) -> Panel:
        """View 3: Monitored Windows Services / Linux Daemons."""
        services = list(self.scan_loop.mod_service.get_live_services().values())
        services.sort(key=lambda x: x.get("service_name", ""))
        display_list = services[:30]

        table = Table(expand=True, box=box.SIMPLE_HEAVY, show_header=True, header_style="bold green")
        table.add_column("Name", width=22)
        table.add_column("Status", width=12)
        table.add_column("Start Type", width=12)
        table.add_column("PID", justify="right", width=6)
        table.add_column("Binary Path")

        for s in display_list:
            status = str(s.get("status", "")).lower()
            st_style = "bold green" if "running" in status or "active" in status else "bold yellow"
            pid_str = str(s.get("pid")) if s.get("pid") else "N/A"

            table.add_row(
                s.get("service_name", "")[:21],
                Text(status.upper(), style=st_style),
                str(s.get("start_type", "")),
                pid_str,
                str(s.get("binpath", ""))[:45],
            )

        return Panel(table, title="[3] Monitored Services & Daemons", border_style="green")

    def render_right_sidebar(self) -> Layout:
        """Renders the 4 stacked sidebar panels (Threat Summary, System Pulse, Flagged, Modules)."""
        sidebar = Layout()
        sidebar.split_column(
            Layout(name="threat_summary", ratio=2),
            Layout(name="system_pulse", ratio=2),
            Layout(name="suspicious_procs", ratio=3),
            Layout(name="module_status", ratio=3),
        )

        counts = self.alert_engine.get_summary_counts()
        # Determine highest severity for border color
        if counts["CRITICAL"] > 0:
            highest_border = "bold red"
        elif counts["HIGH"] > 0:
            highest_border = "red"
        elif counts["MEDIUM"] > 0:
            highest_border = "yellow"
        else:
            highest_border = "green"

        summary_text = Text()
        summary_text.append(f"  CRITICAL : {counts['CRITICAL']}\n", style="bold red")
        summary_text.append(f"  HIGH     : {counts['HIGH']}\n", style="red")
        summary_text.append(f"  MEDIUM   : {counts['MEDIUM']}\n", style="yellow")
        summary_text.append(f"  LOW      : {counts['LOW']}\n", style="dim")
        summary_text.append(f"  INFO     : {counts['INFO']}\n", style="dim white")
        summary_text.append(f"  TOTAL    : {counts['TOTAL']}", style="bold white")

        sidebar["threat_summary"].update(Panel(summary_text, title="Threat Summary", border_style=highest_border))

        pulse = self.scan_loop.pulse_data
        pulse_text = Text()
        pulse_text.append(f"Processes : {pulse.get('active_processes', 0)} active\n", style="bold cyan")
        pulse_text.append(f"CPU Load  : {pulse.get('cpu_percent', 0.0):.1f}%\n", style="yellow")
        pulse_text.append(f"RAM Load  : {pulse.get('memory_percent', 0.0):.1f}%\n", style="magenta")
        pulse_text.append(f"Disk Load : {pulse.get('disk_percent', 0.0):.1f}%", style="green")

        sidebar["system_pulse"].update(Panel(pulse_text, title="System Pulse", border_style="cyan"))

        # Top 5 flagged suspicious alerts
        alerts = self.alert_engine.get_recent_alerts(limit=5)
        suspicious_text = Text()
        if not alerts:
            suspicious_text.append("No suspicious threats detected.", style="dim green")
        else:
            for a in alerts[:5]:
                sev = a.get("severity", "LOW")
                suspicious_text.append(f"[{sev}] {a.get('process_name')} (PID:{a.get('pid')})\n", style="bold red" if sev in ("CRITICAL", "HIGH") else "yellow")
                suspicious_text.append(f"  {a.get('alert_type')}: {a.get('detail')[:35]}...\n", style="dim white")

        sidebar["suspicious_procs"].update(Panel(suspicious_text, title="Suspicious Processes", border_style="red"))

        # Module health status panel
        health = self.scan_loop.module_health
        health_text = Text()
        for mod_name, is_ok in health.items():
            status_str = " [OK] " if is_ok else "[FAIL]"
            style_str = "bold green" if is_ok else "bold red"
            health_text.append(f"{mod_name:<19} : ", style="white")
            health_text.append(f"{status_str}\n", style=style_str)

        sidebar["module_status"].update(Panel(health_text, title="Module Health", border_style="green"))

        return sidebar

    def render_footer(self) -> Panel:
        """Renders footer bar with keybindings and view toggles."""
        if self.status_message and time.time() > self.status_clear_time:
            self.status_message = ""

        footer_text = Text()
        footer_text.append("[ Q ] Quit  ", style="bold red")
        footer_text.append("[ E ] Export HTML Report  ", style="bold green")
        footer_text.append("[ B ] Rebuild Baseline  ", style="bold yellow")
        footer_text.append("[ 1 ] Alerts View  ", style="bold magenta" if self.active_view == 1 else "dim")
        footer_text.append("[ 2 ] Processes View  ", style="bold cyan" if self.active_view == 2 else "dim")
        footer_text.append("[ 3 ] Services View", style="bold green" if self.active_view == 3 else "dim")

        if self.status_message:
            footer_text.append(f"   |   {self.status_message}", style="bold bright_white on dark_green")

        return Panel(footer_text, style="white on dark_blue")

    def _start_keyboard_listener(self) -> None:
        """Launches a dedicated daemon thread to capture blocking keyboard input."""
        def _listener():
            while self.scan_loop.running:
                try:
                    ch = None
                    if is_windows():
                        import msvcrt
                        ch = msvcrt.getwch()
                        # Handle arrow keys and extended function key prefixes
                        if ch in ("\x00", "\xe0"):
                            ext = msvcrt.getwch()
                            if ext in ("K", "H"):
                                ch = "LEFT_ARROW"
                            elif ext in ("M", "P"):
                                ch = "RIGHT_ARROW"
                            else:
                                continue
                        else:
                            ch = ch.lower()
                    else:
                        import select
                        if select.select([sys.stdin], [], [], 0.2)[0]:
                            ch = sys.stdin.read(1).lower()
                        else:
                            continue

                    if ch:
                        self._process_key(ch)
                except Exception:
                    time.sleep(0.05)

        self._listener_thread = threading.Thread(target=_listener, daemon=True)
        self._listener_thread.start()

    def _process_key(self, ch: str) -> None:
        """Executes actions for recognized keyboard inputs."""
        if ch == "q":
            self.scan_loop.running = False
        elif ch == "1":
            self.active_view = 1
        elif ch == "2":
            self.active_view = 2
        elif ch == "3":
            self.active_view = 3
        elif ch == "LEFT_ARROW":
            self.active_view = max(1, self.active_view - 1)
        elif ch == "RIGHT_ARROW":
            self.active_view = min(3, self.active_view + 1)
        elif ch == "e":
            try:
                from reporter.html_exporter import HTMLExporter
                exporter = HTMLExporter(self.scan_loop.db)
                out_file = exporter.generate_report("report.html")
                self.status_message = f"✓ HTML Report exported: {out_file.name}"
                self.status_clear_time = time.time() + 5.0
            except Exception as e:
                self.status_message = f"Export error: {e}"
                self.status_clear_time = time.time() + 5.0
        elif ch == "b":
            try:
                self.scan_loop.rebuild_baseline()
                self.status_message = "✓ Baselines rebuilt successfully!"
                self.status_clear_time = time.time() + 5.0
            except Exception as e:
                self.status_message = f"Rebuild error: {e}"
                self.status_clear_time = time.time() + 5.0

    def build_layout(self) -> Layout:
        """Constructs full Rich application layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3),
        )

        layout["body"].split_row(
            Layout(name="left", ratio=6),
            Layout(name="right", ratio=4),
        )

        layout["header"].update(self.render_header())
        layout["left"].update(self.render_left_panel())
        layout["right"].update(self.render_right_sidebar())
        layout["footer"].update(self.render_footer())

        return layout

    def run_live(self) -> None:
        """Runs the live terminal dashboard with interactive rendering loop."""
        self._start_keyboard_listener()
        with Live(self.build_layout(), refresh_per_second=4, console=self.console, screen=True) as live:
            while self.scan_loop.running:
                try:
                    time.sleep(0.1)
                    live.update(self.build_layout())
                except KeyboardInterrupt:
                    self.scan_loop.running = False
                    break
