# Privacy-First AIOps Observability Platform — Progress & Roadmap

## 1. Architectural Directives & Rules
- **Backend Storage:** Local SQLite storage in `saas_service/local_storage.db` (Cloud Firestore deferred to later phase as instructed).
- **No Heavy / Prohibited Tools:** Zero usage of PostgreSQL, Slack, PagerDuty, or generic external webhooks.
- **Privacy Core Contract:** 
  - `raw_data`, user credentials, API keys, emails, credit cards, real names, and host IP addresses are **NEVER** stored in the transmission buffer or sent to the SaaS platform.
  - A single chokepoint strictly enforces: **Allow-List First -> Redaction Second -> Local Audit Log Third -> SHA-256 Checksumming Fourth**.
  - `unsent_payloads` SQLite table on the Edge stores strictly sanitized `EgressPayload` records.
  - Raw data remains exclusively within the local host machine perimeter (`collector/local_audit.jsonl`).

---

## 2. Multi-Phase Roadmap Status

| Phase | Name | Status | Key Deliverables & Exit Gates |
| :--- | :--- | :---: | :--- |
| **Phase 1** | **Collector Core, Security Chokepoint & Local Buffer** | **VERIFIED** | • Real-time host telemetry (psutil + ping3 every 5s)<br>• Failed-login event tracking & website availability checks<br>• Single payload-builder chokepoint (strict allow-list + redaction)<br>• Local SQLite buffer (`unsent_payloads`) with WAL mode & zero raw data<br>• Local Raw-vs-Redacted View (`local_audit.jsonl`)<br>• Simulator mode (`--simulate cpu_spike / memory_leak / payment_failure / auth_failure`)<br>**Exit Gate 1:** 8/8 Tests Passed. |
| **Phase 2** | **SaaS Transmission, Ingestion API & Offline Replay** | **VERIFIED** | • FastAPI Ingestion Service (`POST /ingest`, `POST /heartbeat`, `POST /auth/token`, `GET /health`)<br>• Dynamic Collector Key & JWT Authentication (`Bearer <JWT>` with Collector Secret login)<br>• Server-side SHA-256 cryptographic verification (`400 checksum_validation_failed`)<br>• Idempotent ingestion (`duplicate: true` on repeat payload_id)<br>• Background Egress Worker (`PENDING -> SENT`, exponential backoff)<br>• Offline Buffering & Automatic Replay with Expired JWT Recovery (Zero Data Loss)<br>• Heartbeat Service (30s interval) & Fleet Collector Registry (`last_seen`)<br>• Dead Letter Queue (`DEAD_LETTER` status)<br>• UTC & Global Readiness (`payload_id`, `collector_id`, `tenant_id`, `event_time_utc`, `source_timezone`)<br>**Exit Gate 2:** 12/12 E2E Tests Passed. |
| **Phase 2.5**| **Local Collector Control Center UI (`collector.exe`)** | **VERIFIED** | • Completely decoupled UI & Collector daemon (closing/minimizing UI never stops collector)<br>• 12 Full Feature Screens & Panels (Dashboard, Telemetry, Raw Data, Redacted Data, Metadata, Egress Proof, Buffer Queue, Connectivity, Security Statistics, Event Logs, System Tray, Start With Windows)<br>• Read-only URI SQLite queries against `database.db` and audit vault `local_audit.jsonl`<br>• Pystray notification area integration + HKCU Run autostart<br>• PyInstaller single-binary distribution (`dist/collector.exe` with bundled CustomTkinter assets)<br>**Exit Gate 2.5:** Clean headless instantiation & PyInstaller compilation verified. |
| **Phase 3** | **Observability Dashboard & Production Gap Closure** | **VERIFIED** | • Real-time host packet loss % calculation (burst ICMP probes via ping3)<br>• Watermark registry & timestamp-aware indexing (`is_out_of_order` tracking for offline flushes)<br>• Self-signed CA & TLS/HTTPS enforcement (`scripts/generate_certs.py`, `certs/ca.crt`, `certs/server.crt`)<br>• Regional ingest routing & data residency boundary enforcement (`403 residency_violation`)<br>• Real-time contextual anomaly detection (rolling Z-scores + multi-metric correlation)<br>• 4 distinct health states (`Healthy`, `Degraded`, `Critical`, `Stale/Offline`) + 60s freshness watchdog<br>• Live web dashboard (`/dashboard`) with Chart.js telemetry & Zero-Trust Egress Proof Panel<br>**Exit Gate 3:** 6/6 Production Readiness Tests Passed. |
| **Phase 4** | **Probable Cause Engine (Rule-based Explainable AIOps)** | **VERIFIED** | • Multi-dimensional incident clustering across temporal windows (sliding window $T \pm 30\text{s}$)<br>• Deterministic Causal Decision Engine / Root Cause Analysis (5 causal patterns)<br>• Mathematical confidence scoring ($0.0 - 1.0$) with zero black-box generative AI hallucinations<br>• Actionable, explainable remediation runbook recommendations paired with each diagnosis<br>• Incident evidence chain and historical timeline reconstruction ($t_{-30\text{s}} \to t_{-20\text{s}} \to t_{0\text{s}}$)<br>• Automatic incident resolution upon telemetry normalization for $\ge 3$ consecutive cycles<br>• Incident REST APIs (`/incidents`, `/incidents/{id}`, `/resolve`) & Observability Dashboard UI integration<br>**Exit Gate 4:** 7/7 RCA Tests Passed. |
| **Phase 4.5**| **Self-Learning Seasonal Baselines & Cyber Attack Engine** | **VERIFIED** | • 168-Slot Matrix (7 days × 24 hours) with Online Continuous Learning (EMA + dynamic variance)<br>• Monday busy traffic vs Sunday idle servers differentiation (Benign vs Worrying fluctuation advisory)<br>• Outside cyber attack detection: Brute-Force floods, Volumetric DDoS, and Slowloris starvation<br>• Alert fatigue suppression, duration tracking, and auto-resolution upon attack subside<br>• Copy-paste firewall & network defense mitigation scripts<br>• 24h seasonal baseline curves for dynamic UI graph envelopes<br>**Exit Gate 4.5:** 7/7 Seasonal & Threat Tests Passed. |
| **Phase 5+**| **Cloud Firestore Integration & Multi-Tenant Rules** | *Planned* | • Cloud Firestore sync with two-company security rules. |

---

## 3. Phase 2 Test Verification Matrix (12 / 12 Tests Passed)

| Test Case | Scenario | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **TEST 1** | Backend Running | `PENDING` -> Transmitted -> `SENT` | Payload marked SENT in SQLite, stored in SaaS | **PASS** |
| **TEST 2** | Backend Offline | Connection Error -> Kept buffered | Kept as `PENDING`, retry_count incremented | **PASS** |
| **TEST 3** | Backend Restored | Multiple buffered payloads replayed | All buffered records replayed, zero data loss | **PASS** |
| **TEST 4** | Duplicate Payload | Repeat submission with same `payload_id` | Handled idempotently with `{"duplicate": true}` | **PASS** |
| **TEST 5** | Invalid API Key | Unauthorized `X-Collector-Key` | HTTP 401 Unauthorized returned | **PASS** |
| **TEST 6** | Corrupted SHA | Payload content modified in transit | HTTP 400 `checksum_validation_failed` | **PASS** |
| **TEST 7** | Dead Letter Queue | Unrecoverable 400 or max retries exceeded | Payload moved to `DEAD_LETTER` status | **PASS** |
| **TEST 8** | Heartbeat | 30s heartbeat pulse sent | `last_seen` & status updated in SaaS Registry | **PASS** |
| **TEST 9** | Dynamic JWT Login | `POST /auth/token` with Collector Secret | Returns valid JWT with tenant & collector claims | **PASS** |
| **TEST 10** | JWT Bearer Auth | `Authorization: Bearer <JWT>` on `/ingest` & `/heartbeat` | Token verified, payload accepted, registry updated | **PASS** |
| **TEST 11** | Expired JWT Handling | Token exceeds TTL expiry | SaaS rejects with HTTP 401 `token_expired` | **PASS** |
| **TEST 12** | Offline Replay + Expired JWT Recovery | Internet OFF -> Payloads buffered -> Internet ON -> JWT expired -> Auto-refresh -> Replay | Egress Worker detects expired JWT, auto-renews via Collector Secret, replays all buffered payloads, marks SENT | **PASS** |

---

## 4. Phase 3 Test Verification Matrix (6 / 6 Tests Passed)

| Test Case | Scenario | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **TEST 1** | Real Packet Loss & Allow-List | Burst ICMP probes via ping3; payload builder filters metric | Packet loss % calculated and included in allow-list; unlisted fields scrubbed | **PASS** |
| **TEST 2** | Outage Replay & Watermark Ordering | 60s outage flush; historical payloads arrive after live payloads | Packets marked `is_out_of_order=True`; sorted by `event_time_utc`; deduplication prevents repeats | **PASS** |
| **TEST 3** | Data Residency Enforcement | Collector submits payload to wrong region endpoint | Ingest rejected with HTTP 403 `residency_violation`; authorized region accepted | **PASS** |
| **TEST 4** | Contextual Anomaly Engine | Multi-metric correlation (High Latency + Packet Loss; CPU + Memory) | Alerts triggered with root-cause context within $\le 15\text{s}$ SLA; resolved on recovery | **PASS** |
| **TEST 5** | 4-State Health & Freshness Watchdog | 60s heartbeat/ingest silence | Health transitions to `Stale/Offline`; auto-recovers to `Healthy` on renewed telemetry | **PASS** |
| **TEST 6** | Egress Proof Panel & Zero PII Leak | SaaS query of `ingested_payloads` and REST proof API | Zero raw data or PII in SaaS store; raw payload fields match cryptographic hashes | **PASS** |

---

## 5. Phase 4 Test Verification Matrix (7 / 7 Tests Passed)

| Test Case | Scenario | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **TEST 1** | Network Degradation RCA | Packet loss $\ge 5\%$ + Latency $\ge 100\text{ms}$ | Diagnoses `NETWORK_LINK_DEGRADATION` ($\ge 88\%$ confidence); outputs MTR/traceroute runbooks | **PASS** |
| **TEST 2** | Memory Leak Monotonic RCA | Monotonic RAM increase over $\ge 3$ consecutive cycles | Diagnoses `MEMORY_LEAK_EXHAUSTION` ($\ge 90\%$ confidence); builds chronological escalation timeline | **PASS** |
| **TEST 3** | Brute-Force Auth Surge RCA | Surge in failed logins $\ge 5$ (or $\ge 10$) | Diagnoses `BRUTE_FORCE_AUTH_ATTACK` ($\ge 95\%$ confidence); outputs IP rate-limiting & MFA runbooks | **PASS** |
| **TEST 4** | Storage I/O Exhaustion RCA | Disk usage $\ge 88\%$ | Diagnoses `STORAGE_IO_EXHAUSTION` ($\ge 90\%$ confidence); outputs disk purge & WAL checkpoint runbooks | **PASS** |
| **TEST 5** | Cascading Multi-Resource Starvation | CPU $\ge 85\%$ + Memory $\ge 80\%$ + Latency $\ge 100\text{ms}$ | Diagnoses `CASCADING_RESOURCE_STARVATION` ($97\%$ confidence); outputs load shedding runbooks | **PASS** |
| **TEST 6** | Incident Clustering & Auto-Resolution | Repeat anomalies cluster under same incident; 3 healthy cycles | Extends timeline without creating duplicate incidents; transitions to `RESOLVED` on recovery | **PASS** |
| **TEST 7** | Incident REST APIs & Dashboard UI | `GET /incidents`, `GET /incidents/{id}`, `POST /resolve` | Full RCA, timeline, and recommendations rendered; manual operator resolution supported | **PASS** |

---

## 6. Phase 4.5 Test Verification Matrix (7 / 7 Tests Passed)

| Test Case | Scenario | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **TEST 1** | Online Continuous Learning | Ingest payloads for Monday 10:00 AM; subsequent observations update slot | Creates 168-slot profile; updates mean & std_dev dynamically via online EMA | **PASS** |
| **TEST 2** | Monday Peak vs Sunday Off-Peak | Evaluates 80% CPU on busy Monday 10:00 AM vs 80% on idle Sunday 03:00 AM | Monday classified as `EXPECTED_WEEKDAY_PEAK` (benign); Sunday classified as `WORRYING_OFFPEAK_SURGE` | **PASS** |
| **TEST 3** | Outside Brute-Force Detection | Ingest surge of 12 failed logins | Detects `OUTSIDE_BRUTE_FORCE_FLOOD` (`CRITICAL`); outputs firewall & rate-limiting runbooks | **PASS** |
| **TEST 4** | Outside Volumetric DDoS Detection | Packet loss 25% + Latency 220ms with low host CPU | Detects `VOLUMETRIC_DDOS_FLOOD` (`CRITICAL`); outputs BGP scrubbing & syncookies runbooks | **PASS** |
| **TEST 5** | Outside Slowloris Detection | Latency 260ms + low CPU (22%) + 0% packet loss | Detects `SLOWLORIS_CONNECTION_STARVATION` (`HIGH`); outputs reverse proxy timeout runbooks | **PASS** |
| **TEST 6** | Alert Fatigue Suppression | Repeat attack traffic updates same threat; 3 calm cycles auto-resolve | Tracks ongoing duration without duplicate alert spam; auto-resolves on attack subside | **PASS** |
| **TEST 7** | Threat & Baseline REST APIs | `GET /seasonal-baseline`, `GET /threats`, `POST /threats/{id}/resolve` | Returns 24h expected normal curves; lists active cyber threats; operator manual resolution | **PASS** |
