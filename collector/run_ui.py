"""
Control Center UI Launcher.
Entrypoint for local execution and PyInstaller packaging into collector.exe.
Supports running from both project root and collector directory.
"""

import argparse
import os
from pathlib import Path
import sys

# Ensure both collector directory and project root are on sys.path
SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
PROJECT_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name == "collector" else SCRIPT_DIR
COLLECTOR_DIR = PROJECT_ROOT / "collector"

for p in [str(COLLECTOR_DIR), str(PROJECT_ROOT)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Handle PyInstaller frozen environment
if getattr(sys, "frozen", False):
    os.chdir(sys._MEIPASS)

try:
    from ui.app import launch_app
    from onboarding import ensure_collector_onboarded
    from config import config
except ImportError:
    from collector.ui.app import launch_app
    from collector.onboarding import ensure_collector_onboarded
    from collector.config import config


def main():
    parser = argparse.ArgumentParser(description="Privacy-First AIOps — Collector Control Center")
    parser.add_argument("--minimized", action="store_true", help="Launch directly into Windows System Tray")
    parser.add_argument("--skip-onboarding", action="store_true", help="Bypass onboarding wizard")
    args = parser.parse_args()

    # Part 3: Collector Registration Wizard on First Startup
    if not args.skip_onboarding:
        try:
            cfg = ensure_collector_onboarded()
            if cfg:
                config.saas.collector_id = cfg.get("collector_id", config.saas.collector_id)
                config.saas.collector_secret = cfg.get("collector_secret", config.saas.collector_secret)
                config.saas.tenant_id = cfg.get("tenant_id", config.saas.tenant_id)
                config.saas.saas_url = cfg.get("saas_url", config.saas.saas_url)
        except Exception as exc:
            print(f"[AIOps.Launcher] Onboarding check warning: {exc}")

    launch_app(start_minimized=args.minimized)


if __name__ == "__main__":
    main()
