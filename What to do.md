# PHASE -1 : 

# 

# What to do ?

# 

1. Collector
2. CPU Monitoring
3. Memory Monitoring
4. Metadata Engine
5. Dashboard
6. AIOps Anomaly Detection

# 

Existing tools :

\---

**Category**	        **Existing Tool**

&#x20; Observability	          Datadog

&#x20; Observability	          Dynatrace

&#x20; Observability	          New Relic

&#x20; Log Analysis	          Splunk

&#x20; Metrics Monitoring	  Prometheus

&#x20; Visualization	          Grafana

&#x20; Distributed Tracing	  Jaeger

&#x20; Distributed Tracing	  Zipkin

&#x20; Cloud Monitoring	  Azure Monitor

&#x20; Cloud Monitoring	  AWS CloudWatch





# COLLECTOR :



* Servers      → psutil
* Applications → APIs
* Routers      → SNMP- USED TO COLLECT INFO FROM : Routers

&#x09;					   Switches

&#x20;                                                  Firewalls

&#x20;                                                  Printers

&#x20;                                                  Network Devices



* Devices      → Syslog - Logs from network devices
* Traffic      → NetFlow - Who is talking to whom on the network? - EX. computerA -- 100mb -- Database Server



* Microservices → OpenTelemetry - collects - Logs

&#x20;                                             Metrics

&#x20;                                             Traces

* Cloud        → Cloud APIs
* Kubernetes   → Kubernetes APIs









ARCHITECTURE :

\---

#### 

&#x20;                   COLLECTOR



&#x20;                        │



&#x20;      ┌──────────────┼──────────────┐



&#x20;        ▼              ▼              ▼



&#x20;     Servers      Applications     Network



&#x20;        │              │              │



&#x20;      psutil           APIs          SNMP



&#x20;        │              │              │



&#x20;        ▼              ▼              ▼



&#x20;    CPU/RAM       Orders/Users   Router Health



&#x20;                       │



&#x20;                       ▼



&#x20;                 OpenTelemetry



&#x20;                       │



&#x20;             Logs + Metrics + Traces



&#x20;                       ▼



&#x20;                 Metadata Engine



&#x20;                       ▼



&#x20;                     SaaS



**Open-Telemetry is a standard way for applications to tell us what's happening inside them.
Collects :**



* Metrics  → Numbers and performance
* Traces   → Request journeys
* Logs     → Errors and messages





##### **System Architecture expected till now :**



┌──────────────────────────────────────────────────────┐

│                CUSTOMER ENVIRONMENT                  │

└──────────────────────────────────────────────────────┘



&#x20;  Infrastructure       Applications         Network

&#x20;  ──────────────       ────────────         ───────

&#x20;  • CPU               • Orders             • Routers

&#x20;  • Memory            • Users              • Switches

&#x20;  • Disk              • Transactions       • Firewalls

&#x20;  • Processes         • Payments           • Traffic

&#x20;  • Network Usage     • Login Events       • Latency



&#x20;        │                  │                  │

&#x20;        ▼                  ▼                  ▼



&#x20;     psutil         APIs / Logs          SNMP

&#x20;                     OpenTelemetry       Syslog

&#x20;                                         NetFlow

&#x20;                                         Ping



&#x20;        └──────────────┬──────────────────┘

&#x20;                       ▼



┌──────────────────────────────────────────────────────┐

│                LOCAL COLLECTOR AGENT                 │

├──────────────────────────────────────────────────────┤

│ • Collect Data                                       │

│ • Normalize                                          │

│ • Filter                                             │

│ • Redact Sensitive Information                       │

│ • Aggregate                                          │

│ • Local Analysis                                     │

└──────────────────────────────────────────────────────┘



&#x20;                       │



&#x20;                       ▼



┌──────────────────────────────────────────────────────┐

│                  METADATA ENGINE                     │

├──────────────────────────────────────────────────────┤

│ Convert Raw Data Into Metadata                       │

│                                                      │

│ Example:                                             │

│ CPU = 85%                                            │

│ Memory = 70%                                         │

│ Failed Logins = 200                                  │

│ Health = Poor                                        │

│ Severity = High                                      │

└──────────────────────────────────────────────────────┘



&#x20;                       │



&#x20;                       ▼



&#x20;         HTTPS + TLS + Authentication



&#x20;                       │



&#x20;                       ▼



========================================================

&#x20;                 SaaS PLATFORM

========================================================



&#x20;                       │



&#x20;                       ▼



┌──────────────────────────────────────────────────────┐

│              INGESTION API LAYER                     │

└──────────────────────────────────────────────────────┘



&#x20;                       │



&#x20;                       ▼



┌──────────────────────────────────────────────────────┐

│                  DATABASE LAYER                      │

├──────────────────────────────────────────────────────┤

│ Telemetry                                             │

│ Metadata                                              │

│ Alerts                                                │

│ Configuration                                         │

│ Tenant Data                                           │

└──────────────────────────────────────────────────────┘



&#x20;                       │



&#x20;                       ▼



┌──────────────────────────────────────────────────────┐

│                  AIOPS ENGINE                        │

├──────────────────────────────────────────────────────┤

│                                                       │

│ 1. Health Scoring                                     │

│    Excellent / Good / Fair / Poor                     │

│                                                       │

│ 2. Anomaly Detection                                  │

│    CPU Spike                                          │

│    Memory Spike                                       │

│    Latency Spike                                      │

│                                                       │

│ 3. Event Correlation                                  │

│    Many Alerts → One Incident                         │

│                                                       │

│ 4. Root Cause Analysis                                │

│                                                       │

│ 5. Recommendations                                    │

│                                                       │

│ 6. Future Autonomous Remediation                      │

└──────────────────────────────────────────────────────┘



&#x20;                       │



&#x20;                       ▼



┌──────────────────────────────────────────────────────┐

│                    DASHBOARD                         │

├──────────────────────────────────────────────────────┤

│                                                      │

│ Live CPU Graph                                       │

│ Live Memory Graph                                    │

│ Live Traffic Graph                                   │

│ Network Health                                       │

│ Security Events                                      │

│ Fleet Health                                         │

│ Tenant Overview                                      │

│ AI Recommendations                                   │

│ Weekly Reports                                       │

│ Monthly Trends                                       │

│ Capacity Forecasts                                   │

│ Anomaly Alerts                                       │

│ Incident Timeline                                    │

│                                                      │

└──────────────────────────────────────────────────────┘



&#x20;                       │



&#x20;                       ▼



┌──────────────────────────────────────────────────────┐

│               COMPANY OPERATIONS TEAM                │

└──────────────────────────────────────────────────────┘





## **RAW DATA VS META DATA:**



==================================================

RAW DATA → METADATA TRANSFORMATION

==================================================



1\. LOGIN FAILURE



RAW DATA (Stays Local)



2026-11-20 10:00:00

User: Manik

Password: abc123

IP: 192.168.1.100



Login Failed



↓



METADATA (Sent to SaaS)



{

&#x20; "event": "AUTH\_FAILURE",

&#x20; "severity": "HIGH",

&#x20; "count": 1

}



==================================================



2\. PAYMENT FAILURE



RAW DATA (Stays Local)



Order #1234



Customer:

Rahul Sharma



Card:

4111-xxxx-xxxx



Payment Failed:

Gateway Timeout



↓



METADATA (Sent to SaaS)



{

&#x20; "event": "PAYMENT\_FAILURE",

&#x20; "failure\_count": 1,

&#x20; "reason": "TIMEOUT"

}



==================================================



3\. NETWORK TRAFFIC



RAW DATA (Stays Local)



Source IP:      10.0.0.5

Destination IP: 10.0.0.20



Bytes Sent: 5000000

Packets:    4000



↓



METADATA (Sent to SaaS)



{

&#x20; "bandwidth": "50Mbps",

&#x20; "packet\_loss": "2%",

&#x20; "network\_health": "GOOD"

}



==================================================



4\. DATABASE LOGS



RAW DATA (Stays Local)



SELECT \* FROM customers

Customer Name: John Doe

Account Number: 123456789



Query Failed



↓



METADATA (Sent to SaaS)



{

&#x20; "db\_response\_time": "120ms",

&#x20; "query\_failures": 1,

&#x20; "health": "FAIR"

}



==================================================



5\. APPLICATION LOG



RAW DATA (Stays Local)



ERROR Payment Failed

User ID: 12345

Order ID: 98765



↓



METADATA (Sent to SaaS)



{

&#x20; "payment\_failures": 1,

&#x20; "service": "PAYMENT",

&#x20; "severity": "HIGH"

}



==================================================



6\. CLOUD TELEMETRY



RAW DATA (Stays Local)



Instance ID: vm-01

CPU: 92%

Memory: 80%

Network In: 500000



↓



METADATA (Sent to SaaS)



{

&#x20; "cpu": 92,

&#x20; "memory": 80,

&#x20; "health": "POOR",

&#x20; "severity": "HIGH"

}



==================================================



OVERALL FLOW



Applications

Servers

Network Devices

Cloud Resources



&#x20;       │

&#x20;       ▼



&#x20;    RAW DATA



&#x20;       │



&#x20;       ▼



┌─────────────────┐

│   COLLECTOR     │

├─────────────────┤

│ Collect         │

│ Filter          │

│ Redact          │

│ Aggregate       │

│ Normalize       │

└─────────────────┘



&#x20;       │



&#x20;       ▼



REMOVE



❌ Passwords

❌ API Keys

❌ Secrets

❌ Customer Names

❌ Credit Card Data

❌ Personal Information



&#x20;       │



&#x20;       ▼



CREATE METADATA



{

&#x20; "cpu": 85,

&#x20; "memory": 70,

&#x20; "failed\_logins": 200,

&#x20; "payment\_failures": 10,

&#x20; "health": "POOR",

&#x20; "severity": "HIGH"

}



&#x20;       │



&#x20;       ▼



SaaS Platform



&#x20;       │



&#x20;       ▼



AIOps Engine



&#x20;       │



&#x20;       ▼



Dashboard

Charts

Alerts

Recommendations

Predictions



==================================================



KEY IDEA



RAW DATA

=

Detailed Sensitive Information



METADATA

=

Operational Summary Information



Example:



RAW DATA:

"Manik Sharma login failed with password abc123"



METADATA:

"Failed Login Count = 1"



==================================================





PHASE - 2 : 

===

DATA SECURITY VIA COLLECTOR in tier 1 itself :

---



Applications

Servers

Network



&#x20;     ↓



Collector



&#x20;     ↓



Filter



&#x20;     ↓



Redact



&#x20;     ↓



Aggregate



&#x20;     ↓



Metadata Generator



&#x20;     ↓



TLS Encrypted Transmission



&#x20;     ↓



SaaS Platform





COLLECTOR ARCHITECTURE UPDATED :

---

**Collector**



&#x20;     **│**



&#x20;     **├── Collection Engine**



&#x20;     **├── Security Pipeline**



&#x20;     **├── Metadata Engine**



&#x20;     **├── Local Buffer**



&#x20;     **├── Alert Engine**



&#x20;     **└── Heartbeat Service**





MAIN FEATURE : 

---

Local Filtering \& Redaction 

**TO BE USED TO AVOID ENCRYPTION :** HTTPS and TLS 1.3





**WHAT EXACTLY ARE WE MONITORING ?

GOAL :** 

1. Collector

2\. Security Pipeline

3\. Metadata Engine

4\. Egress Proof Panel

5\. Heartbeat Service

6\. Offline Detection

7\. Local Buffer

8\. Dashboard

9\. Alerts

10\. AI Features


**WORKING PROJECT :** 



Collector           → Python + psutil

Buffer              → SQLite

Security Pipeline   → Python + Regex

Backend             → FastAPI

Database            → Firebase Firestore

Frontend            → React + Tailwind

Charts              → Chart.js

Deployment          → Render + Vercel

AI                  → Z-Score + Isolation Forest




**TO BE USED :**


Collector

\---------

Python

psutil

ping3

requests



Security

\--------

Regex

Rule Engine



Storage

\--------

SQLite (Buffer)



Backend

\--------

FastAPI



Database

\--------

Firebase Firestore



Frontend

\---------

React

TailwindCSS

Chart.js



Security

\---------

HTTPS

TLS



AI

\-------

Z-Score

Isolation Forest



Deployment

\-----------

Render (Backend)

Vercel (Frontend)



IDs

\-------

UUID



Time

\-------

UTC





