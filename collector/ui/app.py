"""
Collector Control Center — Main Application Window.
Phase 2.5: Local Control Center UI for Privacy-First AIOps Observability Platform.
Built using CustomTkinter with complete independence from the background Collector Service.
Compatible with PyInstaller for distribution as collector.exe.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
import threading
import time
from typing import Any, Dict, List, Optional

try:
    import customtkinter as ctk
    CTK_AVAILABLE = True
except ImportError:
    import tkinter as ctk
    CTK_AVAILABLE = False

import psutil
import socket
import uuid
import requests

try:
    from ..config import config, save_collector_config, get_collector_config_path
    from ..auth_client import auth_client
except (ImportError, ValueError):
    try:
        from collector.config import config, save_collector_config, get_collector_config_path
        from collector.auth_client import auth_client
    except (ImportError, ValueError):
        from config import config, save_collector_config, get_collector_config_path
        from auth_client import auth_client

try:
    from .service_controller import service_controller
    from .state_manager import state_manager
    from .autostart import autostart_manager
    from .tray import SystemTrayManager
except (ImportError, ValueError):
    from ui.service_controller import service_controller
    from ui.state_manager import state_manager
    from ui.autostart import autostart_manager
    from ui.tray import SystemTrayManager

logger = logging.getLogger("AIOps.ControlCenterUI")


class CollectorControlCenterApp:
    """
    Main UI Window for the Collector Control Center.
    Decoupled from the background service: closing or minimizing does NOT kill the collector.
    """

    def __init__(self, start_minimized: bool = False):
        if CTK_AVAILABLE:
            ctk.set_appearance_mode("Dark")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            self.root = ctk.Tk()

        self.root.title("Privacy-First AIOps — Collector Control Center")
        self.root.geometry("1100x720")
        self.root.minsize(950, 600)

        # Handle close button (minimize to tray)
        self.root.protocol("WM_DELETE_WINDOW", self.on_window_close)

        # Initialize System Tray
        self.tray_manager = SystemTrayManager(
            on_open_callback=self.restore_window,
            on_exit_callback=self.on_tray_exit,
            get_status_callback=lambda: service_controller.get_service_status()["status"]
        )
        self.tray_manager.start()

        # Build UI Layout
        self._build_sidebar()
        self._build_main_area()

        # Start periodic background data polling
        self.active_tab = "dashboard"
        self._poll_ui_data()

        if start_minimized:
            self.minimize_to_tray()

    # -------------------------------------------------------------------------
    # UI LAYOUT BUILDERS
    # -------------------------------------------------------------------------
    def _build_sidebar(self):
        """Builds modern left navigation panel."""
        self.sidebar_frame = ctk.CTkFrame(self.root, width=220, corner_radius=0)
        self.sidebar_frame.pack(side="left", fill="y", padx=0, pady=0)

        # App Brand Header
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="🛡️ AIOps Edge",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.pack(padx=20, pady=(20, 5))

        self.sublogo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="Control Center (v1.0.0)",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.sublogo_label.pack(padx=20, pady=(0, 20))

        # Navigation Buttons
        self.nav_buttons = {}
        tabs = [
            ("dashboard", "📊 Dashboard"),
            ("telemetry", "📈 Telemetry"),
            ("egress_proof", "🛡️ Egress Proof"),
            ("audit_viewer", "👁️ Data Viewers"),
            ("queue", "🗄️ Buffer Queue"),
            ("connectivity", "🌐 Connectivity"),
            ("security", "🔒 Security Stats"),
            ("logs", "📜 Event Logs"),
            ("settings", "⚙️ Settings"),
        ]

        for tab_id, label in tabs:
            btn = ctk.CTkButton(
                self.sidebar_frame,
                text=label,
                anchor="w",
                font=ctk.CTkFont(size=13),
                command=lambda t=tab_id: self.switch_tab(t)
            )
            btn.pack(padx=15, pady=4, fill="x")
            self.nav_buttons[tab_id] = btn

        # Bottom Service Quick Toggle
        self.sidebar_bottom = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.sidebar_bottom.pack(side="bottom", fill="x", padx=15, pady=15)

        self.service_status_badge = ctk.CTkLabel(
            self.sidebar_bottom,
            text="● SERVICE: CHECKING",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#F59E0B"
        )
        self.service_status_badge.pack(pady=(0, 5))

    def _build_main_area(self):
        """Builds top status bar and dynamic content frame."""
        self.content_container = ctk.CTkFrame(self.root, corner_radius=0, fg_color="#0F172A")
        self.content_container.pack(side="right", fill="both", expand=True)

        # Top Bar
        self.top_bar = ctk.CTkFrame(self.content_container, height=50, fg_color="#1E293B", corner_radius=0)
        self.top_bar.pack(fill="x", padx=0, pady=0)

        self.header_title = ctk.CTkLabel(
            self.top_bar,
            text="Collector Dashboard",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.header_title.pack(side="left", padx=20, pady=12)

        self.header_meta = ctk.CTkLabel(
            self.top_bar,
            text=f"Collector ID: {config.saas.collector_id}  |  Tenant: {config.saas.tenant_id}",
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8"
        )
        self.header_meta.pack(side="right", padx=20, pady=12)

        # Content Frame
        self.view_frame = ctk.CTkScrollableFrame(self.content_container, fg_color="transparent")
        self.view_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Render Default View (Dashboard)
        self._render_dashboard_view()

    # -------------------------------------------------------------------------
    # TAB SWITCHER
    # -------------------------------------------------------------------------
    def switch_tab(self, tab_id: str):
        self.active_tab = tab_id
        for tid, btn in self.nav_buttons.items():
            if tid == tab_id:
                btn.configure(fg_color=["#3B82F6", "#1D4ED8"])
            else:
                btn.configure(fg_color=["#1E293B", "#334155"])

        # Clear active view
        for widget in self.view_frame.winfo_children():
            widget.destroy()

        if tab_id == "dashboard":
            self.header_title.configure(text="Collector Dashboard")
            self._render_dashboard_view()
        elif tab_id == "telemetry":
            self.header_title.configure(text="Host Telemetry Live Metrics")
            self._render_telemetry_view()
        elif tab_id == "egress_proof":
            self.header_title.configure(text="Egress Proof Multi-Panel Audit")
            self._render_egress_proof_view()
        elif tab_id == "audit_viewer":
            self.header_title.configure(text="Raw & Redacted Data Viewers")
            self._render_audit_view()
        elif tab_id == "queue":
            self.header_title.configure(text="Local SQLite Buffer Queue")
            self._render_queue_view()
        elif tab_id == "connectivity":
            self.header_title.configure(text="SaaS Ingestion Connectivity")
            self._render_connectivity_view()
        elif tab_id == "security":
            self.header_title.configure(text="Security & Privacy Statistics")
            self._render_security_view()
        elif tab_id == "logs":
            self.header_title.configure(text="Edge Event Logs")
            self._render_logs_view()
        elif tab_id == "settings":
            self.header_title.configure(text="Control Center Settings & Startup")
            self._render_settings_view()

    # -------------------------------------------------------------------------
    # FEATURE 1: DASHBOARD VIEW & ONBOARDING WIZARD
    # -------------------------------------------------------------------------
    def _has_valid_credentials(self) -> bool:
        """Checks if collector has provisioned credentials or config."""
        cfg_path = get_collector_config_path()
        return cfg_path.exists()

    def _render_onboarding_view(self):
        """Renders frictionless Onboarding & Cloud Login wizard card."""
        self.header_title.configure(text="Cloud Onboarding & Node Registration")

        card = ctk.CTkFrame(self.view_frame, corner_radius=12, fg_color="#1E293B")
        card.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(
            card,
            text="🚀 Connect Node to Autonomous AIOps Cloud",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#60A5FA"
        ).pack(anchor="w", padx=25, pady=(20, 5))

        ctk.CTkLabel(
            card,
            text="One Account • One Tenant • One Login: Sign in with your unified credentials\nto automatically register this machine into your tenant fleet and start streaming telemetry.",
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8",
            justify="left"
        ).pack(anchor="w", padx=25, pady=(0, 20))

        # Status / Error banner
        self.onboard_status_lbl = ctk.CTkLabel(
            card,
            text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#F87171"
        )
        self.onboard_status_lbl.pack(anchor="w", padx=25, pady=(0, 10))

        # Form fields
        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=25, pady=(0, 20))

        # 1. SaaS Cloud URL
        ctk.CTkLabel(form, text="SaaS Cloud Endpoint:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, sticky="w", pady=6)
        self.entry_saas_url = ctk.CTkEntry(form, width=420)
        default_url = config.saas.saas_url if config.saas.saas_url and "localhost" not in config.saas.saas_url else "https://snow-leopards-aiops-cloud.onrender.com"
        self.entry_saas_url.insert(0, default_url)
        self.entry_saas_url.grid(row=0, column=1, sticky="w", padx=10, pady=6)

        # 2. Email
        ctk.CTkLabel(form, text="Account / Judge Email:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=1, column=0, sticky="w", pady=6)
        self.entry_email = ctk.CTkEntry(form, width=420, placeholder_text="name@domain.com")
        self.entry_email.grid(row=1, column=1, sticky="w", padx=10, pady=6)

        # 3. Password
        ctk.CTkLabel(form, text="Password:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=2, column=0, sticky="w", pady=6)
        self.entry_password = ctk.CTkEntry(form, width=420, show="*")
        self.entry_password.grid(row=2, column=1, sticky="w", padx=10, pady=6)

        # 4. Optional Organization Name (for new signup)
        ctk.CTkLabel(form, text="Org Name (New Signups):", font=ctk.CTkFont(size=12, weight="bold")).grid(row=3, column=0, sticky="w", pady=6)
        self.entry_org = ctk.CTkEntry(form, width=420, placeholder_text="e.g. Judge Evaluation Team, Acme Corp")
        self.entry_org.grid(row=3, column=1, sticky="w", padx=10, pady=6)

        # Buttons Row
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(anchor="w", padx=25, pady=(0, 25))

        self.btn_signin = ctk.CTkButton(
            btn_frame,
            text="🔐 Sign In & Connect",
            fg_color="#3B82F6",
            hover_color="#2563EB",
            font=ctk.CTkFont(weight="bold"),
            command=self._on_click_signin
        )
        self.btn_signin.pack(side="left", padx=(0, 10))

        self.btn_register = ctk.CTkButton(
            btn_frame,
            text="✨ Create Organization & Connect",
            fg_color="#6366F1",
            hover_color="#4F46E5",
            font=ctk.CTkFont(weight="bold"),
            command=self._on_click_register
        )
        self.btn_register.pack(side="left", padx=10)

        self.btn_demo = ctk.CTkButton(
            btn_frame,
            text="⚡ Instant Demo Access",
            fg_color="#10B981",
            hover_color="#059669",
            command=self._on_click_instant_demo
        )
        self.btn_demo.pack(side="left", padx=10)

    def _on_click_signin(self):
        self._set_onboard_loading("Authenticating with Cloud...")
        threading.Thread(target=self._perform_auth, args=("login",), daemon=True).start()

    def _on_click_register(self):
        self._set_onboard_loading("Creating Organization & Provisioning Tenant...")
        threading.Thread(target=self._perform_auth, args=("register",), daemon=True).start()

    def _on_click_instant_demo(self):
        self.entry_email.delete(0, "end")
        self.entry_email.insert(0, "demo1@test.com")
        self.entry_password.delete(0, "end")
        self.entry_password.insert(0, "DemoPassword2026!")
        self._set_onboard_loading("Logging in with Demo Account...")
        threading.Thread(target=self._perform_auth, args=("login",), daemon=True).start()

    def _set_onboard_loading(self, message: str):
        if hasattr(self, 'onboard_status_lbl'):
            self.onboard_status_lbl.configure(text=f"⏳ {message}", text_color="#60A5FA")
        if hasattr(self, 'btn_signin'):
            self.btn_signin.configure(state="disabled")
        if hasattr(self, 'btn_register'):
            self.btn_register.configure(state="disabled")
        if hasattr(self, 'btn_demo'):
            self.btn_demo.configure(state="disabled")

    def _perform_auth(self, mode: str):
        """Background thread executing cloud authentication and collector registration."""
        saas_url = self.entry_saas_url.get().strip().rstrip("/")
        email = self.entry_email.get().strip()
        password = self.entry_password.get().strip()
        org_name = self.entry_org.get().strip() or f"Org-{email.split('@')[0]}"

        if not email or "@" not in email:
            self.root.after(0, lambda: self._on_auth_error("Please enter a valid email address."))
            return
        if not password or len(password) < 6:
            self.root.after(0, lambda: self._on_auth_error("Password must be at least 6 characters."))
            return

        try:
            # 1. Login or Register
            if mode == "register":
                reg_url = f"{saas_url}/api/v1/auth/register-tenant"
                resp = requests.post(reg_url, json={"email": email, "password": password, "tenant_name": org_name}, timeout=12.0)
                if not resp.ok:
                    err_msg = resp.json().get("detail", "Registration failed.")
                    self.root.after(0, lambda: self._on_auth_error(err_msg))
                    return
                auth_data = resp.json()
            else:
                login_url = f"{saas_url}/api/v1/auth/login-tenant"
                resp = requests.post(login_url, json={"email": email, "password": password}, timeout=12.0)
                if not resp.ok:
                    err_msg = resp.json().get("detail", "Invalid email or password.")
                    self.root.after(0, lambda: self._on_auth_error(err_msg))
                    return
                auth_data = resp.json()

            tenant_id = auth_data["tenant_id"]
            jwt_token = auth_data.get("jwt") or auth_data.get("access_token", "")

            # 2. Register Collector Node on this Host
            host_name = socket.gethostname()
            reg_node_url = f"{saas_url}/api/v1/auth/register-collector"
            node_resp = requests.post(reg_node_url, json={
                "hostname": host_name,
                "tenant_id": tenant_id,
                "email": email,
                "password": password
            }, timeout=12.0)

            if node_resp.ok:
                node_data = node_resp.json()
                collector_id = node_data.get("collector_id") or auth_data.get("collector_id") or f"COL-{uuid.uuid4().hex[:6].upper()}"
                collector_secret = node_data.get("collector_secret") or auth_data.get("collector_secret") or auth_data.get("collector_registration_token", "")
            else:
                collector_id = auth_data.get("collector_id") or f"COL-{uuid.uuid4().hex[:6].upper()}"
                collector_secret = auth_data.get("collector_secret") or auth_data.get("collector_registration_token", "")

            # 3. Save to collector_config.json
            saved_cfg = {
                "saas_url": saas_url,
                "email": email,
                "tenant_id": tenant_id,
                "collector_id": collector_id,
                "collector_secret": collector_secret,
                "collector_registration_token": collector_secret,
                "jwt": jwt_token,
                "registered_at": datetime.now(timezone.utc).isoformat()
            }
            save_collector_config(saved_cfg)

            # 4. Update in-memory configurations
            config.saas.saas_url = saas_url
            config.saas.tenant_id = tenant_id
            config.saas.collector_id = collector_id
            config.saas.collector_secret = collector_secret
            auth_client.reload_credentials(saas_url=saas_url, collector_id=collector_id, collector_secret=collector_secret)

            # 5. Start background telemetry service
            service_controller.start_service()

            self.root.after(0, lambda: self._on_auth_success(saved_cfg))

        except Exception as exc:
            self.root.after(0, lambda: self._on_auth_error(f"Connection failed: {str(exc)}"))

    def _on_auth_error(self, err_msg: str):
        if hasattr(self, 'onboard_status_lbl'):
            self.onboard_status_lbl.configure(text=f"❌ {err_msg}", text_color="#F87171")
        if hasattr(self, 'btn_signin'):
            self.btn_signin.configure(state="normal")
        if hasattr(self, 'btn_register'):
            self.btn_register.configure(state="normal")
        if hasattr(self, 'btn_demo'):
            self.btn_demo.configure(state="normal")

    def _on_auth_success(self, data: Dict[str, Any]):
        self.header_meta.configure(
            text=f"Collector ID: {data['collector_id']}  |  Tenant: {data['tenant_id']}"
        )
        self.switch_tab("dashboard")

    def _render_dashboard_view(self):
        # If not onboarded yet, show onboarding wizard
        if not self._has_valid_credentials():
            self._render_onboarding_view()
            return
        # Quick Status Cards
        status_row = ctk.CTkFrame(self.view_frame, fg_color="transparent")
        status_row.pack(fill="x", pady=(0, 15))

        self.card_status = self._create_metric_card(status_row, "Service Status", "CHECKING", "#3B82F6")
        self.card_queue = self._create_metric_card(status_row, "Pending Queue", "0", "#10B981")
        self.card_saas = self._create_metric_card(status_row, "SaaS Connectivity", "TESTING", "#8B5CF6")
        self.card_scrub = self._create_metric_card(status_row, "PII Scrubbed", "0", "#EC4899")

        # System Information & Service Control Card
        control_card = ctk.CTkFrame(self.view_frame, corner_radius=10, fg_color="#1E293B")
        control_card.pack(fill="x", pady=10, padx=5)

        ctk.CTkLabel(control_card, text="Collector Daemon Control", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 10))

        info_text = (
            f"• Collector ID:  {config.saas.collector_id}\n"
            f"• Tenant ID:     {config.saas.tenant_id}\n"
            f"• Agent Version: 1.0.0 (Production Stable)\n"
            f"• SaaS Endpoint: {config.saas.saas_url}\n"
            f"• Independence:  Runs in background even if Control Center is closed."
        )
        ctk.CTkLabel(control_card, text=info_text, justify="left", font=ctk.CTkFont(family="Consolas", size=12)).pack(anchor="w", padx=20, pady=(0, 15))

        btn_row = ctk.CTkFrame(control_card, fg_color="transparent")
        btn_row.pack(anchor="w", padx=20, pady=(0, 20))

        ctk.CTkButton(btn_row, text="▶ Start Service", width=120, fg_color="#10B981", hover_color="#059669",
                      command=self._on_start_service_click).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_row, text="⏹ Stop Service", width=120, fg_color="#EF4444", hover_color="#DC2626",
                      command=self._on_stop_service_click).pack(side="left", padx=10)
        ctk.CTkButton(btn_row, text="🔄 Restart Service", width=120, fg_color="#3B82F6", hover_color="#2563EB",
                      command=self._on_restart_service_click).pack(side="left", padx=10)

    # -------------------------------------------------------------------------
    # FEATURE 2: TELEMETRY SCREEN
    # -------------------------------------------------------------------------
    def _render_telemetry_view(self):
        container = ctk.CTkFrame(self.view_frame, corner_radius=10, fg_color="#1E293B")
        container.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(container, text="Live Host Telemetry (Every 2 Seconds)", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(15, 15))

        # CPU
        self.cpu_label = ctk.CTkLabel(container, text="CPU Usage: 0.0%", font=ctk.CTkFont(size=14))
        self.cpu_label.pack(anchor="w", padx=20, pady=(5, 2))
        self.cpu_bar = ctk.CTkProgressBar(container, width=500, height=14)
        self.cpu_bar.set(0.0)
        self.cpu_bar.pack(anchor="w", padx=20, pady=(0, 15))

        # Memory
        self.mem_label = ctk.CTkLabel(container, text="Memory Usage: 0.0%", font=ctk.CTkFont(size=14))
        self.mem_label.pack(anchor="w", padx=20, pady=(5, 2))
        self.mem_bar = ctk.CTkProgressBar(container, width=500, height=14)
        self.mem_bar.set(0.0)
        self.mem_bar.pack(anchor="w", padx=20, pady=(0, 15))

        # Disk
        self.disk_label = ctk.CTkLabel(container, text="Disk Usage: 0.0%", font=ctk.CTkFont(size=14))
        self.disk_label.pack(anchor="w", padx=20, pady=(5, 2))
        self.disk_bar = ctk.CTkProgressBar(container, width=500, height=14)
        self.disk_bar.set(0.0)
        self.disk_bar.pack(anchor="w", padx=20, pady=(0, 15))

        # Latency & Network
        self.lat_label = ctk.CTkLabel(container, text="Latency to 8.8.8.8: 0.0 ms  |  Failed Logins: 0", font=ctk.CTkFont(size=14))
        self.lat_label.pack(anchor="w", padx=20, pady=(5, 20))

    # -------------------------------------------------------------------------
    # FEATURE 6: EGRESS PROOF VIEWER
    # -------------------------------------------------------------------------
    def _render_egress_proof_view(self):
        container = ctk.CTkFrame(self.view_frame, corner_radius=10, fg_color="#1E293B")
        container.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(
            container,
            text="Egress Proof Multi-Panel Viewer\nGuarantees Raw Data is never transmitted while showing the sealed egress payload.",
            font=ctk.CTkFont(size=14, weight="bold"),
            justify="left"
        ).pack(anchor="w", padx=20, pady=(15, 10))

        records = state_manager.get_audit_records(limit=1)
        if not records:
            ctk.CTkLabel(container, text="No Egress Proof records found yet in local_audit.jsonl.", text_color="gray").pack(padx=20, pady=20)
            return

        rec = records[-1]
        grid = ctk.CTkFrame(container, fg_color="transparent")
        grid.pack(fill="both", expand=True, padx=15, pady=10)

        # Panel 1: Raw Data (Local Only)
        p1 = self._create_proof_box(grid, "1. RAW DATA (LOCAL ONLY - NEVER SENT)", rec.get("raw_data"), "#DC2626")
        p1.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        # Panel 2: Redacted Data
        p2 = self._create_proof_box(grid, "2. REDACTED DATA (SCRUBBED)", rec.get("redacted_data"), "#F59E0B")
        p2.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

        # Panel 3: Metadata
        p3 = self._create_proof_box(grid, "3. NORMALIZED METADATA", rec.get("metadata"), "#3B82F6")
        p3.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        # Panel 4: Transmitted Payload
        tx_payload = {
            "payload_id": rec.get("payload_id"),
            "data": rec.get("redacted_data"),
            "metadata": rec.get("metadata")
        }
        p4 = self._create_proof_box(grid, "4. TRANSMITTED EGRESS PAYLOAD (SHA-256 SEALED)", tx_payload, "#10B981")
        p4.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

    # -------------------------------------------------------------------------
    # FEATURES 3, 4, 5: AUDIT & DATA VIEWERS
    # -------------------------------------------------------------------------
    def _render_audit_view(self):
        container = ctk.CTkFrame(self.view_frame, corner_radius=10, fg_color="#1E293B")
        container.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(container, text="Local Raw vs Redacted Audit Records", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 10))

        records = state_manager.get_audit_records(limit=5)
        if not records:
            ctk.CTkLabel(container, text="No local audit records recorded yet.", text_color="gray").pack(padx=20, pady=20)
            return

        for r in reversed(records):
            card = ctk.CTkFrame(container, fg_color="#0F172A", corner_radius=8)
            card.pack(fill="x", padx=15, pady=6)

            header = f"Audit ID: {r.get('audit_id')} | Time: {r.get('timestamp')}"
            ctk.CTkLabel(card, text=header, font=ctk.CTkFont(size=12, weight="bold"), text_color="#38BDF8").pack(anchor="w", padx=15, pady=(8, 2))

            if r.get("dropped_fields"):
                ctk.CTkLabel(card, text=f"Dropped Unallowed Fields: {r.get('dropped_fields')}", font=ctk.CTkFont(size=11), text_color="#F87171").pack(anchor="w", padx=15)
            if r.get("scrubbed_detections"):
                ctk.CTkLabel(card, text=f"Scrubbed Secrets/PII: {r.get('scrubbed_detections')}", font=ctk.CTkFont(size=11), text_color="#FBBF24").pack(anchor="w", padx=15)

            body_str = json.dumps({"raw_data": r.get("raw_data"), "redacted_data": r.get("redacted_data")}, indent=2)
            tb = ctk.CTkTextbox(card, height=100, font=ctk.CTkFont(family="Consolas", size=11))
            tb.insert("1.0", body_str)
            tb.configure(state="disabled")
            tb.pack(fill="x", padx=15, pady=(5, 10))

    # -------------------------------------------------------------------------
    # FEATURE 7: BUFFER QUEUE VIEWER
    # -------------------------------------------------------------------------
    def _render_queue_view(self):
        container = ctk.CTkFrame(self.view_frame, corner_radius=10, fg_color="#1E293B")
        container.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(container, text="SQLite Buffer Queue (database.db)", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 10))

        counts = state_manager.get_queue_statistics()
        row = ctk.CTkFrame(container, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 15))

        ctk.CTkLabel(row, text=f"PENDING: {counts['pending']}", font=ctk.CTkFont(size=13, weight="bold"), text_color="#F59E0B").pack(side="left", padx=(0, 20))
        ctk.CTkLabel(row, text=f"SENT: {counts['sent']}", font=ctk.CTkFont(size=13, weight="bold"), text_color="#10B981").pack(side="left", padx=20)
        ctk.CTkLabel(row, text=f"FAILED: {counts['failed']}", font=ctk.CTkFont(size=13, weight="bold"), text_color="#F87171").pack(side="left", padx=20)
        ctk.CTkLabel(row, text=f"DEAD LETTER: {counts['dead_letter']}", font=ctk.CTkFont(size=13, weight="bold"), text_color="#EF4444").pack(side="left", padx=20)

        # Recent Payloads Table
        recent = state_manager.get_recent_payloads(limit=10)
        table_frame = ctk.CTkFrame(container, fg_color="#0F172A", corner_radius=8)
        table_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        header_text = f"{'Payload ID':<38} {'Status':<12} {'Timestamp':<22} {'Retries':<8}"
        ctk.CTkLabel(table_frame, text=header_text, font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color="#94A3B8").pack(anchor="w", padx=10, pady=(10, 5))

        for item in recent:
            color = "#10B981" if item["status"] == "SENT" else "#F59E0B" if item["status"] == "PENDING" else "#EF4444"
            line = f"{item['payload_id']:<38} {item['status']:<12} {item['timestamp']:<22} {item['retry_count']:<8}"
            lbl = ctk.CTkLabel(table_frame, text=line, font=ctk.CTkFont(family="Consolas", size=11), text_color=color)
            lbl.pack(anchor="w", padx=10, pady=2)

    # -------------------------------------------------------------------------
    # FEATURE 8: CONNECTIVITY PANEL
    # -------------------------------------------------------------------------
    def _render_connectivity_view(self):
        container = ctk.CTkFrame(self.view_frame, corner_radius=10, fg_color="#1E293B")
        container.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(container, text="SaaS Platform Connectivity & Heartbeat Health", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 10))

        conn = state_manager.check_saas_connectivity()
        last_tx = state_manager.get_last_transmission_time()

        status_text = "CONNECTED (HTTP 200)" if conn["is_connected"] else "OFFLINE / UNREACHABLE"
        status_color = "#10B981" if conn["is_connected"] else "#EF4444"

        details = (
            f"• Ingestion SaaS URL:    {conn['endpoint']}\n"
            f"• Connection Status:     {status_text}\n"
            f"• Latency to SaaS:       {conn['latency_ms']} ms\n"
            f"• Last Successful Sync:  {last_tx}\n"
            f"• Heartbeat Frequency:   Every 30 seconds"
        )
        ctk.CTkLabel(container, text=details, justify="left", font=ctk.CTkFont(family="Consolas", size=13), text_color=status_color).pack(anchor="w", padx=20, pady=15)

    # -------------------------------------------------------------------------
    # FEATURE 9: SECURITY STATISTICS
    # -------------------------------------------------------------------------
    def _render_security_view(self):
        container = ctk.CTkFrame(self.view_frame, corner_radius=10, fg_color="#1E293B")
        container.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(container, text="Security & Privacy Scrubbing Statistics", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 10))

        sec = state_manager.get_security_statistics()
        grid = ctk.CTkFrame(container, fg_color="transparent")
        grid.pack(fill="x", padx=15, pady=10)

        self._create_stat_badge(grid, "Passwords Removed", str(sec["passwords_removed"]), "#EF4444", 0, 0)
        self._create_stat_badge(grid, "API Keys Removed", str(sec["api_keys_removed"]), "#F59E0B", 0, 1)
        self._create_stat_badge(grid, "Credit Cards Removed", str(sec["credit_cards_removed"]), "#EC4899", 1, 0)
        self._create_stat_badge(grid, "Emails Redacted", str(sec["emails_removed"]), "#3B82F6", 1, 1)
        self._create_stat_badge(grid, "Personal Names Masked", str(sec["names_removed"]), "#10B981", 2, 0)
        self._create_stat_badge(grid, "Unallowed Fields Dropped", str(sec["fields_dropped"]), "#8B5CF6", 2, 1)

    # -------------------------------------------------------------------------
    # FEATURE 10: LOGS VIEWER
    # -------------------------------------------------------------------------
    def _render_logs_view(self):
        container = ctk.CTkFrame(self.view_frame, corner_radius=10, fg_color="#1E293B")
        container.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(container, text="Edge Operational Event Logs", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 10))

        self.log_textbox = ctk.CTkTextbox(container, height=350, font=ctk.CTkFont(family="Consolas", size=11))
        self.log_textbox.pack(fill="both", expand=True, padx=20, pady=(5, 15))

        recent_payloads = state_manager.get_recent_payloads(limit=25)
        lines = []
        for p in recent_payloads:
            lines.append(f"[{p['timestamp']}] [TRANSMISSION] Payload ID: {p['payload_id']} | Status: {p['status']} | Retries: {p['retry_count']}")
        self.log_textbox.insert("1.0", "\n".join(lines) if lines else "No event logs recorded.")
        self.log_textbox.configure(state="disabled")

    # -------------------------------------------------------------------------
    # FEATURE 12: SETTINGS & AUTOSTART
    # -------------------------------------------------------------------------
    def _render_settings_view(self):
        container = ctk.CTkFrame(self.view_frame, corner_radius=10, fg_color="#1E293B")
        container.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(container, text="Settings & Windows Startup Configuration", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 10))

        # Start with Windows switch
        is_autostart = autostart_manager.is_autostart_enabled()
        self.autostart_switch = ctk.CTkSwitch(
            container,
            text="Start Collector Automatically With Windows (HKCU Run Key)",
            font=ctk.CTkFont(size=13),
            command=self._on_autostart_toggle
        )
        if is_autostart:
            self.autostart_switch.select()
        else:
            self.autostart_switch.deselect()
        self.autostart_switch.pack(anchor="w", padx=20, pady=15)

        ctk.CTkLabel(
            container,
            text="When enabled, the Collector will launch in background daemon mode on system boot.",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).pack(anchor="w", padx=20, pady=(0, 20))

        # Cloud Tenant Management
        ctk.CTkLabel(container, text="Cloud Tenant & Account Connection", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        ctk.CTkLabel(container, text=f"• Active Tenant: {config.saas.tenant_id}\n• Collector ID:  {config.saas.collector_id}\n• SaaS Cloud:   {config.saas.saas_url}",
                     font=ctk.CTkFont(family="Consolas", size=12), justify="left").pack(anchor="w", padx=20, pady=(0, 10))

        ctk.CTkButton(
            container,
            text="🔌 Reconnect / Switch Tenant Account",
            fg_color="#F59E0B",
            hover_color="#D97706",
            font=ctk.CTkFont(weight="bold"),
            command=self._on_switch_account_click
        ).pack(anchor="w", padx=20, pady=(0, 25))

    def _on_switch_account_click(self):
        """Resets saved collector_config.json and presents the onboarding wizard."""
        cfg_file = get_collector_config_path()
        if cfg_file.exists():
            try:
                cfg_file.unlink()
            except Exception:
                pass
        self.switch_tab("dashboard")

    # -------------------------------------------------------------------------
    # BACKGROUND POLLER
    # -------------------------------------------------------------------------
    def _poll_ui_data(self):
        """Polls live metrics and updates UI safely every 2.5 seconds."""
        try:
            status = service_controller.get_service_status()
            queue = state_manager.get_queue_statistics()
            sec = state_manager.get_security_statistics()

            # Update sidebar badge
            badge_color = "#10B981" if status["is_running"] else "#EF4444"
            self.service_status_badge.configure(
                text=f"● SERVICE: {status['status']}",
                text_color=badge_color
            )

            # Update dashboard cards if active
            if self.active_tab == "dashboard" and hasattr(self, "card_status"):
                self.card_status.configure(text=status["status"])
                self.card_queue.configure(text=str(queue["pending"]))
                self.card_scrub.configure(text=str(sec["total_scrubbed_events"]))

            # Update live telemetry if active
            if self.active_tab == "telemetry" and hasattr(self, "cpu_bar"):
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory().percent
                disk = psutil.disk_usage(Path.cwd().anchor or ".").percent

                self.cpu_bar.set(cpu / 100.0)
                self.cpu_label.configure(text=f"CPU Usage: {cpu:.1f}%")
                self.mem_bar.set(mem / 100.0)
                self.mem_label.configure(text=f"Memory Usage: {mem:.1f}%")
                self.disk_bar.set(disk / 100.0)
                self.disk_label.configure(text=f"Disk Usage: {disk:.1f}%")

        except Exception as exc:
            pass

        # Schedule next poll
        self.root.after(2500, self._poll_ui_data)

    # -------------------------------------------------------------------------
    # HELPER COMPONENT BUILDERS
    # -------------------------------------------------------------------------
    def _create_metric_card(self, parent, title: str, default_val: str, color: str):
        card = ctk.CTkFrame(parent, fg_color="#1E293B", corner_radius=8, width=170, height=75)
        card.pack(side="left", padx=5, fill="both", expand=True)
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11), text_color="gray").pack(pady=(8, 2))
        lbl = ctk.CTkLabel(card, text=default_val, font=ctk.CTkFont(size=18, weight="bold"), text_color=color)
        lbl.pack(pady=(0, 8))
        return lbl

    def _create_proof_box(self, parent, title: str, content: Any, border_color: str):
        frame = ctk.CTkFrame(parent, fg_color="#0F172A", border_color=border_color, border_width=1, corner_radius=8)
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=11, weight="bold"), text_color=border_color).pack(anchor="w", padx=10, pady=(8, 4))
        tb = ctk.CTkTextbox(frame, height=140, font=ctk.CTkFont(family="Consolas", size=10))
        tb.insert("1.0", json.dumps(content, indent=2) if isinstance(content, (dict, list)) else str(content))
        tb.configure(state="disabled")
        tb.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        return frame

    def _create_stat_badge(self, parent, title: str, count: str, color: str, row: int, col: int):
        badge = ctk.CTkFrame(parent, fg_color="#0F172A", corner_radius=8)
        badge.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")
        ctk.CTkLabel(badge, text=count, font=ctk.CTkFont(size=22, weight="bold"), text_color=color).pack(padx=15, pady=(10, 2))
        ctk.CTkLabel(badge, text=title, font=ctk.CTkFont(size=12)).pack(padx=15, pady=(0, 10))
        parent.columnconfigure(col, weight=1)

    # -------------------------------------------------------------------------
    # WINDOW LIFECYCLE & TRAY HANDLERS
    # -------------------------------------------------------------------------
    def on_window_close(self):
        """When user clicks 'X', minimize to system tray instead of killing the app."""
        self.minimize_to_tray()

    def minimize_to_tray(self):
        self.root.withdraw()

    def restore_window(self):
        self.root.after(0, self._restore_main_thread)

    def _restore_main_thread(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def on_tray_exit(self):
        """User chose Exit from tray: closes UI but leaves collector service running."""
        self.tray_manager.stop()
        self.root.quit()

    def _on_start_service_click(self):
        service_controller.start_service()

    def _on_stop_service_click(self):
        service_controller.stop_service()

    def _on_restart_service_click(self):
        service_controller.restart_service()

    def _on_autostart_toggle(self):
        if self.autostart_switch.get() == 1:
            autostart_manager.enable_autostart()
        else:
            autostart_manager.disable_autostart()

    def run(self):
        self.root.mainloop()


def launch_app(start_minimized: bool = False):
    app = CollectorControlCenterApp(start_minimized=start_minimized)
    app.run()
