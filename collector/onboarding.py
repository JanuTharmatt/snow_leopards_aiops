"""
Collector First-Startup Onboarding Wizard.
Phase 5.5: Multi-Tenant Self-Service Onboarding.

Features:
- Detects if collector_config.json exists on node.
- If missing on first run, displays an interactive graphical Onboarding Wizard (or CLI fallback).
- Collects Organization Name, User Email, Password, and SaaS URL.
- Registers collector via POST /api/v1/auth/register-collector.
- Saves credentials locally to collector_config.json.
- On subsequent startups, automatically loads configuration and connects to SaaS immediately.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import platform
import socket
import sys
from typing import Any, Dict, Optional
import urllib.request
import urllib.error

try:
    import customtkinter as ctk
    CTK_AVAILABLE = True
except ImportError:
    try:
        import tkinter as ctk
        CTK_AVAILABLE = False
    except ImportError:
        ctk = None
        CTK_AVAILABLE = False

logger = logging.getLogger("AIOps.Onboarding")

# Determine base directory for configuration file
if getattr(sys, "frozen", False):
    # PyInstaller executable location
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent

CONFIG_FILE_PATH = APP_DIR / "collector_config.json"
DEFAULT_SAAS_URL = os.environ.get("SAAS_URL", "http://localhost:8000")


def is_onboarded() -> bool:
    """Checks whether the collector has already been registered on this machine."""
    if not CONFIG_FILE_PATH.exists():
        return False
    try:
        data = json.loads(CONFIG_FILE_PATH.read_text(encoding="utf-8"))
        return bool(data.get("collector_id") and data.get("tenant_id") and data.get("collector_secret"))
    except Exception:
        return False


def load_collector_config() -> Optional[Dict[str, Any]]:
    """Loads locally saved collector credentials."""
    if not CONFIG_FILE_PATH.exists():
        return None
    try:
        return json.loads(CONFIG_FILE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to parse collector_config.json: %s", exc)
        return None


def save_collector_config(config_data: Dict[str, Any]) -> None:
    """Persists collector registration to collector_config.json."""
    CONFIG_FILE_PATH.write_text(json.dumps(config_data, indent=2), encoding="utf-8")
    logger.info("Collector configuration persisted to %s", CONFIG_FILE_PATH)


def register_collector_api(
    saas_url: str,
    org_name: str,
    email: str,
    password: str,
    hostname: Optional[str] = None
) -> Dict[str, Any]:
    """
    Submits collector registration request to SaaS backend.
    """
    clean_url = saas_url.rstrip("/")
    endpoint = f"{clean_url}/api/v1/auth/register-collector"
    host = hostname or socket.gethostname() or platform.node() or "windows-node"

    payload = {
        "hostname": host,
        "tenant_name": org_name,
        "email": email,
        "password": password
    }

    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=req_data,
        headers={"Content-Type": "application/json"}
    )

    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data
    except urllib.error.HTTPError as he:
        err_msg = he.read().decode("utf-8")
        try:
            err_json = json.loads(err_msg)
            raise RuntimeError(err_json.get("detail", str(he)))
        except Exception:
            raise RuntimeError(f"HTTP {he.code}: {err_msg}")
    except Exception as exc:
        raise RuntimeError(f"Cannot connect to SaaS at {clean_url}: {str(exc)}")


class OnboardingWizardUI:
    """Tkinter/CustomTkinter GUI dialog for first-startup node setup."""

    def __init__(self, saas_url: str = DEFAULT_SAAS_URL):
        self.saas_url = saas_url
        self.registration_result: Optional[Dict[str, Any]] = None

        if CTK_AVAILABLE and hasattr(ctk, "CTk"):
            ctk.set_appearance_mode("Dark")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            import tkinter as tk
            self.root = tk.Tk()

        self.root.title("SNOW LEOPARDS — Collector Node Setup")
        self.root.geometry("540x520")
        self.root.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        import tkinter as tk

        # Title
        title_label = tk.Label(
            self.root,
            text="❄️ SNOW LEOPARDS Collector Setup",
            font=("Segoe UI", 14, "bold"),
            bg="#1e1e2d" if CTK_AVAILABLE else "#f0f2f5",
            fg="#ffffff" if CTK_AVAILABLE else "#111827"
        )
        title_label.pack(pady=(20, 5))

        subtitle = tk.Label(
            self.root,
            text="Multi-Tenant Node Registration (< 1 minute setup)",
            font=("Segoe UI", 9),
            bg="#1e1e2d" if CTK_AVAILABLE else "#f0f2f5",
            fg="#9ca3af" if CTK_AVAILABLE else "#4b5563"
        )
        subtitle.pack(pady=(0, 15))

        # Form Frame
        form_frame = tk.Frame(self.root, bg="#1e1e2d" if CTK_AVAILABLE else "#f0f2f5")
        form_frame.pack(padx=30, fill="x")

        # SaaS URL
        tk.Label(form_frame, text="SaaS Server Endpoint:", font=("Segoe UI", 9, "bold"), anchor="w",
                 bg="#1e1e2d" if CTK_AVAILABLE else "#f0f2f5", fg="#e5e7eb" if CTK_AVAILABLE else "#1f2937").pack(fill="x", pady=(5, 2))
        self.saas_entry = tk.Entry(form_frame, font=("Segoe UI", 10))
        self.saas_entry.insert(0, self.saas_url)
        self.saas_entry.pack(fill="x", pady=(0, 10))

        # Organization Name
        tk.Label(form_frame, text="Organization / Team Name:", font=("Segoe UI", 9, "bold"), anchor="w",
                 bg="#1e1e2d" if CTK_AVAILABLE else "#f0f2f5", fg="#e5e7eb" if CTK_AVAILABLE else "#1f2937").pack(fill="x", pady=(5, 2))
        self.org_entry = tk.Entry(form_frame, font=("Segoe UI", 10))
        self.org_entry.insert(0, "Judge Evaluation Lab")
        self.org_entry.pack(fill="x", pady=(0, 10))

        # Email
        tk.Label(form_frame, text="Operator / Judge Email:", font=("Segoe UI", 9, "bold"), anchor="w",
                 bg="#1e1e2d" if CTK_AVAILABLE else "#f0f2f5", fg="#e5e7eb" if CTK_AVAILABLE else "#1f2937").pack(fill="x", pady=(5, 2))
        self.email_entry = tk.Entry(form_frame, font=("Segoe UI", 10))
        self.email_entry.insert(0, "judge@demo.com")
        self.email_entry.pack(fill="x", pady=(0, 10))

        # Password
        tk.Label(form_frame, text="Account Password:", font=("Segoe UI", 9, "bold"), anchor="w",
                 bg="#1e1e2d" if CTK_AVAILABLE else "#f0f2f5", fg="#e5e7eb" if CTK_AVAILABLE else "#1f2937").pack(fill="x", pady=(5, 2))
        self.pwd_entry = tk.Entry(form_frame, show="*", font=("Segoe UI", 10))
        self.pwd_entry.insert(0, "JudgeSecure2026!")
        self.pwd_entry.pack(fill="x", pady=(0, 15))

        # Status Label
        self.status_label = tk.Label(
            self.root,
            text="",
            font=("Segoe UI", 9, "bold"),
            bg="#1e1e2d" if CTK_AVAILABLE else "#f0f2f5",
            fg="#ef4444"
        )
        self.status_label.pack(pady=(0, 10))

        # Submit Button
        self.btn_submit = tk.Button(
            self.root,
            text="🚀 Register Node & Connect to Cloud",
            font=("Segoe UI", 10, "bold"),
            bg="#6366f1",
            fg="#ffffff",
            activebackground="#4f46e5",
            activeforeground="#ffffff",
            relief="flat",
            padx=15,
            pady=8,
            command=self._on_submit
        )
        self.btn_submit.pack(pady=(5, 15))

    def _on_submit(self):
        s_url = self.saas_entry.get().strip()
        org = self.org_entry.get().strip()
        email = self.email_entry.get().strip()
        pwd = self.pwd_entry.get()

        if not s_url or not org or not email or not pwd:
            self.status_label.config(text="Please fill in all required fields.", fg="#ef4444")
            return

        self.btn_submit.config(state="disabled", text="Registering Node...")
        self.status_label.config(text="Contacting SaaS service...", fg="#6366f1")
        self.root.update()

        try:
            res = register_collector_api(
                saas_url=s_url,
                org_name=org,
                email=email,
                password=pwd
            )

            # Build config payload
            config_data = {
                "collector_id": res["collector_id"],
                "tenant_id": res["tenant_id"],
                "collector_secret": res["collector_secret"],
                "hostname": res.get("hostname", socket.gethostname()),
                "registered_at": res.get("registered_at", datetime.now(timezone.utc).isoformat()),
                "saas_url": s_url,
                "org_name": org,
                "email": email
            }
            save_collector_config(config_data)
            self.registration_result = config_data

            self.status_label.config(
                text=f"Success! Node {res['collector_id']} provisioned under {res['tenant_id']}",
                fg="#10b981"
            )
            self.root.update()
            self.root.after(1200, self.root.destroy)

        except Exception as exc:
            self.status_label.config(text=str(exc), fg="#ef4444")
            self.btn_submit.config(state="normal", text="🚀 Register Node & Connect to Cloud")

    def run(self) -> Optional[Dict[str, Any]]:
        self.root.mainloop()
        return self.registration_result


def run_cli_onboarding() -> Optional[Dict[str, Any]]:
    """Command-line fallback onboarding when no graphical display is present."""
    print("==================================================")
    print("SNOW LEOPARDS — Collector Onboarding Wizard")
    print("==================================================")
    saas_url = input(f"SaaS Server URL [{DEFAULT_SAAS_URL}]: ").strip() or DEFAULT_SAAS_URL
    org = input("Organization Name [Judge Evaluation Team]: ").strip() or "Judge Evaluation Team"
    email = input("User Email [judge@demo.com]: ").strip() or "judge@demo.com"
    pwd = input("Password [JudgeSecure2026!]: ").strip() or "JudgeSecure2026!"

    print("Registering collector node with SaaS platform...")
    try:
        res = register_collector_api(saas_url, org, email, pwd)
        config_data = {
            "collector_id": res["collector_id"],
            "tenant_id": res["tenant_id"],
            "collector_secret": res["collector_secret"],
            "hostname": res.get("hostname", socket.gethostname()),
            "registered_at": res.get("registered_at", datetime.now(timezone.utc).isoformat()),
            "saas_url": saas_url,
            "org_name": org,
            "email": email
        }
        save_collector_config(config_data)
        print(f"Success! Node '{res['collector_id']}' provisioned for tenant '{res['tenant_id']}'.")
        return config_data
    except Exception as exc:
        print(f"Registration failed: {exc}")
        return None


def ensure_collector_onboarded() -> Dict[str, Any]:
    """
    Main entrypoint called at startup of collector.exe.
    Returns active collector config, running wizard if not yet onboarded.
    """
    if is_onboarded():
        cfg = load_collector_config()
        if cfg:
            return cfg

    # Node not configured: launch onboarding wizard
    if os.environ.get("HEADLESS_ONBOARDING") or ctk is None:
        cfg = run_cli_onboarding()
    else:
        try:
            wizard = OnboardingWizardUI()
            cfg = wizard.run()
        except Exception:
            cfg = run_cli_onboarding()

    if not cfg:
        # Fallback to local default demo config if wizard was cancelled
        logger.warning("Onboarding wizard cancelled. Using fallback default demo credentials.")
        cfg = {
            "collector_id": "COLL-001",
            "tenant_id": "TENANT-001",
            "collector_secret": "SECRET-COLL-DEMO-001",
            "hostname": socket.gethostname(),
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "saas_url": DEFAULT_SAAS_URL
        }
        save_collector_config(cfg)
    return cfg


if __name__ == "__main__":
    ensure_collector_onboarded()
