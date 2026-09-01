"""ProcessGuard — Windows Service & Process Monitoring Agent.

Entry point for initializing system baselines, running background scan loops,
rendering Rich terminal UI telemetry, and exporting HTML security reports.
"""

import argparse
from pathlib import Path
import sys
import time

from config.loader import ConfigLoader
from database.db_manager import DBManager
from dashboard.ui import TerminalDashboard
from engine.alert_engine import AlertEngine
from engine.scan_loop import ScanLoop
from reporter.html_exporter import HTMLExporter
from utils.logger import setup_logging


def parse_args() -> argparse.Namespace:
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="ProcessGuard — Windows Service & Process Monitoring Agent",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--export-html",
        type=str,
        default=None,
        nargs="?",
        const="report.html",
        help="Export security report to dark-themed HTML file and exit or periodically",
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Run in headless daemon mode without Rich terminal UI",
    )
    return parser.parse_args()


def main() -> None:
    """Main execution flow."""
    args = parse_args()

    # 1. Setup logging
    logger = setup_logging()
    logger.info("Initializing ProcessGuard Security Monitoring Agent...")

    # 2. Load Configuration
    config = ConfigLoader(args.config)

    # 3. Initialize SQLite Database Manager
    db = DBManager(config.db_abs_path)

    # 4. Initialize Alert Engine
    alert_engine = AlertEngine(db)

    # 5. Initialize Scan Loop and start background thread
    scan_loop = ScanLoop(config, db, alert_engine)
    scan_loop.start()

    # 6. HTML Export standalone check
    if args.export_html:
        exporter = HTMLExporter(db)
        out_file = exporter.generate_report(args.export_html)
        logger.info(f"HTML Report successfully exported to: {out_file}")

    # 7. Start Dashboard or Headless Loop
    if args.no_ui:
        logger.info("Running in headless daemon mode. Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Shutdown requested.")
    else:
        try:
            dashboard = TerminalDashboard(scan_loop, alert_engine)
            dashboard.run_live()
        except KeyboardInterrupt:
            pass

    # Clean shutdown
    logger.info("Stopping background monitoring tasks...")
    scan_loop.stop()
    logger.info("ProcessGuard shutdown complete.")


if __name__ == "__main__":
    main()
