"""
Control Center UI Launcher (Root Shortcut).
Allows running 'python run_ui.py' directly from the repository root.
"""

import argparse
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent
COLLECTOR_DIR = ROOT_DIR / "collector"

if str(COLLECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(COLLECTOR_DIR))

from ui.app import launch_app


def main():
    parser = argparse.ArgumentParser(description="Privacy-First AIOps — Collector Control Center")
    parser.add_argument("--minimized", action="store_true", help="Launch directly into Windows System Tray")
    args = parser.parse_args()

    launch_app(start_minimized=args.minimized)


if __name__ == "__main__":
    main()
