# ZTShield
### Zero-Trust Network Defense & Attack Simulation Platform

ZTShield is a cybersecurity capstone project designed to demonstrate zero-trust network defense, network segmentation, security event monitoring, attack detection, event correlation, and risk analysis in a controlled virtual lab environment.

The platform integrates network security telemetry, a Python-based backend, a SQLite database, and a React dashboard to provide centralized visibility into security events.

---

## 1. Project Objectives

- Demonstrate network segmentation using pfSense.
- Monitor network activity using Suricata.
- Collect and ingest security events from network security components.
- Centralize security events using a FastAPI backend.
- Detect and analyze suspicious activity.
- Correlate related security events.
- Calculate security risk scores.
- Display security telemetry through a web dashboard.
- Validate network access-control policies through controlled testing.

## 2. Key Features

- **Network segmentation:** Separate lab networks into USER, SERVER, DMZ, MANAGEMENT, and TELEMETRY zones.
- **Intrusion detection:** Suricata-based network monitoring and custom detection rules.
- **Firewall telemetry:** pfSense integration for firewall event collection.
- **Centralized ingestion:** API endpoints for Suricata and pfSense events.
- **Attack detection:** Dedicated intelligence module for attack analysis.
- **Event correlation:** Identify relationships between security events.
- **IP context:** Supporting IP-context analysis.
- **Risk scoring:** Assess event risk using the intelligence engine.
- **Incident management:** Create, retrieve, and update incident status.
- **Dashboard:** Visualize alerts, severity distribution, sensors, and security activity.
- **Persistent storage:** Store security events in SQLite.

## 3. Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, FastAPI |
| API server | Uvicorn |
| Database | SQLite |
| ORM | SQLAlchemy |
| Configuration | Pydantic Settings |
| Frontend | React, TypeScript |
| Frontend tooling | Vite |
| Icons | Lucide React |
| Network monitoring | Suricata |
| Firewall | pfSense |
| Testing | Pytest, HTTPX |
| Virtual lab | Kali Linux, Metasploitable2, pfSense |

## 4. System Architecture

The platform follows a telemetry collection and centralized analysis architecture.

```text
                 CONTROLLED LAB ENVIRONMENT
                           |
             +-------------+-------------+
             |                           |
          pfSense                     Suricata
       Firewall Events              Network Events
             |                           |
             v                           v
    pfSense Syslog/API              EVE JSON Logs
             |                           |
             v                           v
    pfSense Receiver               EVE Watcher
             |                           |
             +-------------+-------------+
                           |
                           v
                    FastAPI Backend
                           |
              +------------+------------+
              |            |            |
              v            v            v
         Detection     Correlation   Risk Scoring
         Intelligence  Intelligence  Intelligence
              |            |            |
              +------------+------------+
                           |
                           v
                     SQLite Database
                           |
                           v
                    REST API Endpoints
                           |
                           v
                  React/TypeScript UI
                           |
                           v
                  Security Dashboard
```

## 5. Network Lab Design

The ZTShield lab uses separate network zones to demonstrate segmentation and access-control policies.

| Network zone | Subnet | Purpose |
|---|---|---|
| USER | 192.168.10.0/24 | User network |
| SERVER | 192.168.20.0/24 | Server network |
| DMZ | 192.168.30.0/24 | Demilitarized zone |
| MANAGEMENT | 192.168.40.0/24 | Administrative access |
| TELEMETRY | 192.168.56.0/24 | Security telemetry network |

pfSense acts as the firewall and routing control point between the lab networks.

Access between zones is governed by firewall rules. The lab includes validation of permitted management access and blocked DMZ-to-management access.

## 6. Backend Intelligence Modules

The platform includes a modular security intelligence implementation located in `backend/intelligence/`. These modules provide attack detection, event correlation, IP-context analysis, risk assessment, and orchestration capabilities.

| Module | Responsibility |
|---|---|
| `attack_detection.py` | Identifies potential attack patterns from security events. |
| `event_correlation.py` | Correlates related security events, including events from different sources. |
| `ip_context.py` | Evaluates IP communication context and network relationships. |
| `risk_scoring.py` | Assesses security risk based on event severity and communication context. |
| `orchestrator.py` | Coordinates intelligence analysis and incident evidence generation. |

### Intelligence Processing Workflow

The orchestrator provides a separately invokable analysis workflow that:

1. Retrieves previously persisted security alerts.
2. Evaluates attack patterns and cross-source event correlations.
3. Analyzes IP communication context.
4. Calculates risk assessments.
5. Creates or updates incidents and associated evidence and timeline records.

**Integration status:** The intelligence modules are implemented and independently tested. However, the orchestration workflow is not currently invoked automatically by the FastAPI telemetry ingestion endpoints. Live event ingestion and intelligence analysis therefore operate as separate workflows.

## 7. Repository Structure

```text
ZTShield/
│
├── backend/
│   ├── intelligence/
│   │   ├── attack_detection.py
│   │   ├── event_correlation.py
│   │   ├── ip_context.py
│   │   ├── orchestrator.py
│   │   └── risk_scoring.py
│   ├── main.py
│   ├── pfsense_syslog_receiver.py
│   ├── watch_eve.py
│   ├── ingest_eve_file.py
│   ├── inspect_pfsense_events.py
│   └── requirements.txt
│
├── detection/
│   └── ztshield.rules
│
├── docs/
│
├── frontend/
│   └── src/
│       ├── App.tsx
│       └── App.css
│
├── samples/
│
├── tests/
│   ├── test_api.py
│   ├── test_attack_detection.py
│   ├── test_event_correlation.py
│   ├── test_orchestrator.py
│   └── test_risk_scoring.py
│
├── .gitignore
├── pytest.ini
└── README.md
```

## 8. Prerequisites

The development environment used for this project includes:

- Windows 10/11
- Python 3.13
- Node.js and npm
- Git
- Visual Studio Code
- Suricata 8.x
- pfSense virtual machine
- Virtualization software for the lab machines

Network interface names and IP addresses may need to be adapted to the host environment.

## 9. Installation and Setup

### 9.1 Clone the repository

```powershell
git clone https://github.com/LaxmanRompella/ZTShield.git
cd ZTShield
```

### 9.2 Set up the Python environment

```powershell
py -3.13 -m venv backend\.venv

.\backend\.venv\Scripts\python.exe -m pip install --upgrade pip

.\backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

### 9.3 Configure backend ingestion authentication

The backend reads its ingestion token from `backend/.env`.

Generate a 64-character hexadecimal token:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Create `backend/.env` with the generated value:

```text
INGEST_TOKEN=YOUR_GENERATED_64_CHARACTER_TOKEN
```

Keep this file private. Never commit real credentials or tokens to GitHub.

### 9.4 Install frontend dependencies

```powershell
cd frontend

npm.cmd install

cd ..
```

## 10. Running the Platform

Open separate PowerShell terminals for the backend, frontend, and telemetry processes.

### Terminal 1 — Backend API

```powershell
cd D:\Laxman_Rompella_Capstone_Projects\ZTShield

.\backend\.venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000 --app-dir backend
```

Health endpoint:

`http://127.0.0.1:8000/api/health`

### Terminal 2 — Frontend dashboard

```powershell
cd D:\Laxman_Rompella_Capstone_Projects\ZTShield\frontend

npm.cmd run dev
```

Open:

`http://localhost:5173`

The current frontend development configuration uses the local backend address `http://127.0.0.1:8000`.

### Terminal 3 — Suricata event watcher

After starting Suricata and confirming that its EVE JSON log is being generated:

```powershell
cd D:\Laxman_Rompella_Capstone_Projects\ZTShield

.\backend\.venv\Scripts\python.exe `
    .\backend\watch_eve.py `
    .\suricata-logs\YOUR_LIVE_LOG_DIRECTORY\eve.json `
    --api-url http://127.0.0.1:8000/api/ingest/suricata `
    --capture-mode live `
    --poll-interval 1
```

Replace `YOUR_LIVE_LOG_DIRECTORY` with the actual Suricata log directory.

The watcher monitors EVE JSON events and submits eligible events to the backend ingestion endpoint.

### Suricata detection rule

The repository includes a controlled ICMP detection rule in `detection/ztshield.rules`.

```text
alert icmp any any -> any any (msg:"ZTShield ICMP test"; itype:8; sid:1000001; rev:1;)
```

This rule is used for controlled ICMP detection validation.

## 11. API Reference

The backend exposes REST API endpoints.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | API information |
| GET | `/api/health` | Backend health |
| GET | `/api/alerts` | Retrieve alerts |
| POST | `/api/alerts` | Create a manual alert |
| POST | `/api/incidents` | Create an incident |
| GET | `/api/incidents` | Retrieve incidents |
| GET | `/api/incidents/{incident_id}` | Retrieve an incident |
| PATCH | `/api/incidents/{incident_id}/status` | Update incident status |
| POST | `/api/ingest/suricata` | Ingest Suricata events |
| POST | `/api/ingest/pfsense` | Ingest pfSense events |
| GET | `/api/summary` | Retrieve dashboard summary |
| GET | `/api/sensors` | Retrieve sensor information |

Interactive API documentation is available at:

`http://127.0.0.1:8000/docs`

Ingestion endpoints require the configured authentication token.

## 12. Testing and Validation

The following results have been observed during project validation.

| Test | Observed result |
|---|---|
| Backend regression suite | 64 passed |
| Suricata configuration validation | Successful |
| Suricata live capture | Engine started |
| Live EVE JSON generation | Verified |
| Suricata watcher ingestion | Six controlled events ingested |
| API event retrieval | All six event IDs retrieved |
| SQLite-backed API health | Healthy |
| Frontend production build | Successful |
| Frontend-to-backend connection | Verified |
| Management-to-DMZ SSH access | Allowed as configured |
| DMZ-to-Management SSH access | Blocked by pfSense |

The six controlled Suricata event IDs were verified through the alerts API:

- `SURICATA-A81FC63AB1BF`
- `SURICATA-2F4740B43E8D`
- `SURICATA-0882F2349392`
- `SURICATA-B96A3A3EF3ED`
- `SURICATA-1981C3E2EFD4`
- `SURICATA-7AA36804F639`

### Run backend tests

```powershell
cd D:\Laxman_Rompella_Capstone_Projects\ZTShield

.\backend\.venv\Scripts\python.exe -m pytest -q
```

### Build the frontend

```powershell
cd frontend

npm.cmd run build
```

## 13. Security Considerations

- Keep ingestion credentials outside source control.
- Use firewall policies to control inter-zone communication.
- Restrict administrative access to the management network.
- Validate telemetry source authentication.
- Keep databases, logs, and environment files out of public repositories.
- Use an isolated and authorized lab environment for attack simulation.

The current project is a controlled lab implementation and should not be treated as a production-ready enterprise security platform without further hardening and testing.

## 14. Limitations and Future Enhancements

Potential future improvements include:

- Integration of additional security sensors.
- Expanded Suricata detection rules.
- More comprehensive attack simulation scenarios.
- Enhanced threat intelligence enrichment.
- Advanced incident investigation and response workflows.
- Role-based access control.
- Production deployment configuration.
- Additional automated end-to-end tests.
- Improved sensor health monitoring and policy integrations.

## 15. Project Status

ZTShield has demonstrated:

- Network segmentation and firewall policy validation.
- Live Suricata telemetry collection.
- Centralized event ingestion and persistence.
- Security intelligence modules.
- API-based alert and incident management.
- Dashboard integration.
- Backend regression testing.

Further enhancements and deployment hardening remain part of the future scope.

---

**Project:** ZTShield — Zero-Trust Network Defense & Attack Simulation Platform

**Repository:** ZTShield

**Documentation:** Project README
