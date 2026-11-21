# ❄️ SNOW LEOPARDS
### Privacy-First Autonomous AIOps & Observability Cloud Platform

[![Tests](https://img.shields.io/badge/tests-29%2F29%20passed-emerald)](tests/)
[![Architecture](https://img.shields.io/badge/architecture-zero--trust%20egress-indigo)](docs/SETUP_GUIDE.md)
[![Security](https://img.shields.io/badge/firestore.rules-hardened%20multi--tenant-blue)](firestore.rules)
[![Platform](https://img.shields.io/badge/runtime-Python%203.11%20%7C%20FastAPI%20%7C%20CustomTkinter-blueviolet)](saas_service/)
[![Design](https://img.shields.io/badge/UI-Frosted%20Glassmorphism-violet)](saas_service/web/templates/dashboard.html)

**SNOW LEOPARDS** is an enterprise-grade, privacy-first autonomous AIOps and observability platform engineered for high-security, multi-tenant hybrid cloud and edge infrastructure.

Unlike traditional APM tools that extract unscrubbed telemetry, raw database queries, and customer PII to third-party SaaS vendors, SNOW LEOPARDS enforces **Zero-Trust Egress**: all metrics are cryptographically sanitized, stripped of PII/secrets, hashed via SHA-256, and correlated locally on edge nodes before metadata-only egress.

---

## 🌟 Key Architectural Pillars

### 1. 🛡️ Zero-Trust Egress & Data Privacy
- **Client-Side Regex Sanitization:** Multi-pattern scanning intercepts passwords, credit cards, emails, and API keys.
- **Cryptographic Egress Proofs:** Every ingested payload is stamped with a SHA-256 hash seal and verified on receipt.
- **Air-Gapped Local Buffer:** SQLite local buffer prevents data loss during upstream network outages.

### 2. 🧠 Deterministic Causal RCA Engine
- **No Hallucinations:** Pure deterministic rule-based causal graphs and multi-metric clustering.
- **Explainable Confidence:** Mathematical confidence scores (0.0 to 1.0) paired with step-by-step audit timelines.
- **Automated Runbooks:** Direct CLI and PowerShell remediation commands generated on incident trigger.

### 3. 🕒 168-Slot Self-Learning Seasonal AI
- **Day $\times$ Hour Baselining:** Maintains 168 rolling slots (7 days $\times$ 24 hours) for dynamic thresholding.
- **Context-Aware Alerting:** Automatically distinguishes normal business-hour traffic spikes from weekend anomalies.

### 4. 🌐 Outside Cyber-Attack Radar
- **Heuristic Threat Detection:** Detects credential stuffing floods, volumetric DDoS, and Slowloris starvation.
- **Automated Countermeasures:** Generates `netsh`, `iptables`, and edge proxy rules to block attackers.

### 5. 👥 Multi-Tenant Cloud & Dual-Mode Firestore
- **Strict Boundary Isolation:** Enforces multi-tenancy across endpoints; cross-tenant access is rejected with `HTTP 403 Forbidden`.
- **Cloud Firestore Ready:** Production-grade security rules in `firestore.rules` with seamless fallback to SQLite.

### 6. 🧪 Demo Laboratory
- **Instant Live Incident Injection:** Interactive dashboard buttons to test CPU spikes, memory leaks, brute force attacks, DDoS floods, and Slowloris starvation in real time.

---

## ⚡ Quickstart (< 2 Minutes)

### Option A: Local Evaluation
1. **Start the SaaS Platform & Dashboard:**
   ```bat
   start_saas_dashboard.bat
   ```
   *Dashboard opens at:* `http://localhost:8000/dashboard`
2. **Launch Edge Collector:**
   ```bat
   start_collector_ui.bat
   ```
   *On first run, the Onboarding Wizard will automatically configure the node and connect to the SaaS cloud.*

### Option B: Build Standalone Windows Executable
Package the collector into `collector.exe` with zero Python runtime dependency:
```bat
scripts\build_collector.bat
```
Output executable: `dist\collector.exe`

---

## 🧪 Testing & Verification

Run the complete test suite (29 unit & integration tests):
```powershell
python -m unittest discover -s tests -v
```
**Results:** `Ran 29 tests in 1.594s — OK`

---

## 📂 Repository Structure

```
CICADA/
├── collector/                     # Edge Telemetry Collector & Control Center UI
│   ├── onboarding.py              # First-startup registration wizard
│   ├── run_ui.py                  # Control Center launcher
│   └── collector_app.spec         # PyInstaller single-file spec
├── saas_service/                  # SaaS Ingestion Service & Dashboard
│   ├── routes/                    # REST APIs (Auth, Ingest, Dashboard, Phase 5, Demo Lab)
│   ├── services/                  # RCA, Seasonal, Threat, Risk, Forecasting, Remediation, Copilot
│   └── web/templates/             # Glassmorphism HTML/JS dashboards & Auth views
├── frontend/                      # Standalone React + Firebase Edge App
│   ├── src/auth/                  # Firebase Auth, Login, Register, Forgot Password
│   └── package.json               # Frontend dependencies
├── tests/                         # Full automated test suite (29 tests)
├── scripts/                       # PyInstaller packaging and build automation
├── docs/                          # Detailed Judge Setup & Evaluation Guide
├── firestore.rules                # Hardened Multi-Tenant Firestore Security Rules
├── Dockerfile                     # Cloud container build definition
├── render.yaml                    # Render.com Cloud Backend Blueprint
├── vercel.json                    # Vercel Frontend Edge Config
└── .env.example                   # Environment configuration template
```

---

## 📜 Evaluation Guide
For full judge evaluation instructions, walkthrough scenarios, and multi-tenant isolation tests, see **[docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)**.
