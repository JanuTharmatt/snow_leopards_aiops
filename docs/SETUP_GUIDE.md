# SNOW LEOPARDS — Judge Evaluation & Setup Guide
## Privacy-First Autonomous AIOps Platform (Phase 5.5)

Welcome, Evaluators and Judges! This guide walks you through setting up and evaluating the **SNOW LEOPARDS** Autonomous AIOps Platform in **under 2 minutes**.

---

## ⚡ 1. Two-Minute Judge Quickstart

### Step 1: Start the SaaS Platform
Open a terminal in the project directory and run:
```bat
start_saas_dashboard.bat
```
*(Or manually: `uvicorn saas_service.main:app --port 8000`)*
- SaaS Web Dashboard opens automatically at: [http://localhost:8000](http://localhost:8000)

---

### Step 2: Collector Setup on Any Windows Machine
You can run the collector either from the pre-built executable or directly via Python:

#### Option A: Run Standalone Executable (No Python Required)
Run `collector.exe` (or build it using `scripts\build_collector.bat`):
```bat
dist\collector.exe
```

#### Option B: Run Collector via Python
```bat
start_collector_ui.bat
```

#### First-Startup Onboarding Wizard:
1. When launched on a new laptop, the **SNOW LEOPARDS Onboarding Wizard** automatically opens.
2. Enter your Organization Name (e.g., `Judge Demo Corp`), Email (`judge@demo.com`), and Password (`JudgePass2026!`).
3. Click **"Register Node & Connect to Cloud"**.
4. The collector automatically:
   - Registers your new organization (`tenant_<hex>`)
   - Provisions a unique collector node (`COL-<hex>`)
   - Obtains an authenticated JWT
   - Saves credentials to `collector_config.json`
   - Begins streaming live telemetry and heartbeats to the SaaS cloud!

---

## 🛡️ 2. Multi-Tenant Isolation Verification

Every tenant is completely air-gapped with zero-trust isolation:

1. **Log in as Tenant A:**
   - Go to [http://localhost:8000/login](http://localhost:8000/login)
   - Click **"⚡ Instant Evaluator Demo Access"** (logs in as `TENANT-001`).
   - You will see strictly nodes and telemetry belonging to `TENANT-001`.

2. **Verify Multi-Tenant Boundary Security:**
   - Attempt to query another tenant's data (e.g. `TENANT-ALPHA`) using Tenant A's token:
   ```bash
   curl -H "Authorization: Bearer <TOKEN_A>" "http://localhost:8000/api/v1/dashboard/overview?tenant_id=TENANT-ALPHA"
   ```
   - **Result:** Immediate **`HTTP 403 Forbidden`**:
     `"Forbidden: Tenant isolation violation. Authenticated tenant 'TENANT-001' cannot access foreign tenant 'TENANT-ALPHA'."`

---

## 🧪 3. Demo Laboratory — Live Interactive Incident Testing

Open the Dashboard at [http://localhost:8000/dashboard](http://localhost:8000/dashboard) and click the **"Demo Laboratory"** tab:

| Incident Button | Triggered Signature | AI Diagnosis & RCA | Automated Runbook |
|---|---|---|---|
| **CPU Spike** | Sustained 96.8% compute load | Runaway compute loop / thread contention | Isolate thread, throttle ETL, scale replica |
| **Memory Leak** | Monotonic RAM climb (84% $\rightarrow$ 95.2%) | Uncollected application heap leak | Memory profile snapshot, rolling worker restart |
| **Brute Force Attack** | 16 rapid failed login attempts | Outside Automated Credential Stuffing | Netsh/iptables rate limiter, edge CAPTCHA challenge |
| **DDoS Flood** | 18.5% packet drop + 215ms latency | Volumetric Uplink DDoS Flood | BGP Flowspec scrubbing, TCP syncookies |
| **Slowloris Attack** | 265ms latency with 18% CPU & 0% loss | HTTP Socket Pool Starvation | Nginx 5s timeout, connection limit per IP |

Clicking any button instantly triggers live detection across the deterministic causal RCA Engine, logs an incident, and displays the actionable remediation runbook in real time.

---

## 🏗️ 4. Cloud & Production Deployment

- **Cloud Firestore**: Rules configured in `firestore.rules` with strict multi-tenant access controls. Dual-mode storage in `saas_service/services/firestore_storage.py` syncs to Firestore when GCP credentials are provided, with zero-downtime SQLite fallback.
- **Vercel**: `vercel.json` and `frontend/package.json` for frontend edge hosting.
- **Render.com**: `render.yaml` for instant backend cloud deployment.
- **Docker**: `Dockerfile` for containerized hosting.
