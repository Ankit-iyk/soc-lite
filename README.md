# SOC Lite — Security Operations Center Dashboard

> Lightweight, deterministic threat detection and incident management platform for security operations.

[![Tests](https://img.shields.io/badge/Tests-449%20passed-brightgreen.svg)]()
[![Lint](https://img.shields.io/badge/Lint-0%20warnings-brightgreen.svg)]()
[![Node](https://img.shields.io/badge/Node.js-22.x-blue.svg)]()
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-blue.svg)]()
[![License](https://img.shields.io/badge/License-ISC-lightgrey.svg)]()

---

## 1. Project Overview & Architecture

**SOC Lite** is a full-stack Security Operations Center (SOC) web application built to simulate and demonstrate threat ingestion, real-time deterministic detection, triage, incident response, asset tracking, threat intelligence (IOC) correlation, and audit logging.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Frontend (React 19 + Vite 8)                 │
│  Tailwind CSS v4 • Recharts • Route Code-Splitting • Lucide UI  │
└─────────────────────────────────┬───────────────────────────────┘
                                  │ HTTP / JSON (Axios + JWT)
┌─────────────────────────────────▼───────────────────────────────┐
│                    Backend (Node.js 22 + Express 5)             │
│  RBAC Middleware • Central Audit • PDFKit • Detection Pipeline  │
└──────────────────┬──────────────────────────────┬───────────────┘
                   │ Prisma ORM                   │ HTTP REST
┌──────────────────▼──────────┐        ┌──────────▼───────────────┐
│        PostgreSQL 18        │        │ Threat Intel Providers   │
│  Alerts • Incidents • Assets│        │ VirusTotal • AbuseIPDB   │
│  ThreatIndicators • AuditLog│        │ AlienVault OTX (opt.)    │
└─────────────────────────────┘        └──────────────────────────┘
```

---

## 2. Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 19, Vite 8, Tailwind CSS v4, React Router v6, Recharts, Lucide Icons |
| **Backend** | Node.js 22 (ES Modules), Express 5, Helmet, CORS, PDFKit |
| **Database & ORM** | PostgreSQL 18, Prisma ORM 6 |
| **Authentication** | Stateless JWT (Bearer token), bcryptjs password hashing |
| **Testing** | Node 22 native test runner (`node:test`, `node:assert/strict`), oxlint |

---

## 3. Implemented Phases

- **Phase 1:** Project scaffold, linting, and tooling setup.
- **Phase 2:** Database schema, Prisma ORM, and JWT authentication.
- **Phase 3:** Log ingestion engine and syslog parser.
- **Phase 4:** Deterministic detection engine (SSH Brute Force, Port Scan, Suspicious IP, Suspicious Access).
- **Phase 5:** Alert management, evidence linkage, and lifecycle tracking.
- **Phase 6:** Incident tracking, status transitions, alert correlation, and investigation notes.
- **Phase 7:** SOC Dashboard with KPIs, live time-series charts, and severity breakdowns.
- **Phase 8:** Asset management, infrastructure inventory, and audit timeline.
- **Phase 9:** Threat Intelligence (IOCs), external provider adapters, and auto-correlation.
- **Phase 10:** PDF security reports generator with live JSON preview and streamed downloads.
- **Phase 11:** Comprehensive quality assurance, cross-module testing, and bug remediation.
- **Phase 12:** Final polish, RBAC hardening, centralized audit trail, and route code-splitting.

---

## 4. Role-Based Access Control (RBAC) Matrix

| Functional Module | Operation | ADMIN | ANALYST | VIEWER |
|---|---|:---:|:---:|:---:|
| **Authentication** | Login, logout, session check | ✅ | ✅ | ✅ |
| **Dashboard** | Live metrics, time-series charts, KPIs | ✅ | ✅ | ✅ |
| **Log Ingestion** | Ingest raw logs (`POST /api/logs/ingest`) | ✅ | ✅ | ❌ |
| **Detection Engine** | Trigger detection pipeline (`POST /api/detection/run`) | ✅ | ✅ | ❌ |
| **Detection Rules** | Modify rule parameters (`PUT /api/rules/:id`) | ✅ | ❌ | ❌ |
| **Alert Management** | Browse and inspect alert evidence chains | ✅ | ✅ | ✅ |
| **Alert Lifecycle** | Acknowledge and update alert status | ✅ | ✅ | ❌ |
| **Incident Tracking** | Browse and inspect incident records | ✅ | ✅ | ✅ |
| **Incident Mutations**| Create incidents, change status, add notes, link alerts | ✅ | ✅ | ❌ |
| **Asset Management** | Browse infrastructure assets | ✅ | ✅ | ✅ |
| **Asset Mutations** | Register, update, and decommission assets | ✅ | ✅ | ❌ |
| **Asset Deletion** | Permanently delete asset from database | ✅ | ❌ | ❌ |
| **Threat Intelligence**| Browse indicators, view correlations | ✅ | ✅ | ✅ |
| **IOC Mutations** | Register and update threat indicators | ✅ | ✅ | ❌ |
| **Threat Lookups** | Query external threat providers | ✅ | ✅ | ❌ |
| **IOC Deletion** | Permanently delete threat indicator | ✅ | ❌ | ❌ |
| **Security Reports** | Preview live report JSON in browser | ✅ | ✅ | ✅ |
| **Report Download** | Generate and download PDF security reports | ✅ | ✅ | ❌ |
| **Audit Logging** | Query system-wide security audit history | ✅ | ✅ | ❌ |

---

## 5. Local Setup & Installation

### Prerequisites
- **Node.js**: v22.18.0 or newer
- **npm**: v10.9.3 or newer
- **PostgreSQL**: v16 or v18 running locally

### Step 1: Clone Repository
```bash
git clone https://github.com/Ankit-iyk/soc-lite.git
cd soc-lite
```

### Step 2: Install Dependencies
```bash
# Install backend dependencies
cd backend
npm install

# Install frontend dependencies
cd ../frontend
npm install
cd ..
```

### Step 3: Configure Environment Variables
Copy the example environment template in `backend/`:
```bash
cd backend
cp .env.example .env
```

Edit `backend/.env` with your PostgreSQL database credentials and JWT secret:
```env
PORT=3000
NODE_ENV=development
CORS_ORIGIN=http://localhost:5173
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/soc_lite_db?schema=public
JWT_SECRET=your-random-32-byte-hex-secret
JWT_EXPIRES_IN=8h

# Optional external threat intelligence providers (can leave blank):
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
```

### Step 4: Database Setup & Seed
```bash
cd backend
# Generate Prisma Client
npx prisma generate

# Push schema to database
npx prisma db push

# Seed default baseline users, detection rules, assets, and threat IOCs
npm run db:seed
```

### Seed Accounts Created:
- **Administrator:** `admin@soclite.local` / `Admin@SOC2026!` (Role: `ADMIN`)
- **Security Analyst:** `analyst@soclite.local` / `Analyst@SOC2026!` (Role: `ANALYST`)
- **Executive Viewer:** `viewer@soclite.local` / `Viewer@SOC2026!` (Role: `VIEWER`)

---

## 6. Running the Application

### Start Backend Development Server (Port 3000)
```bash
cd backend
npm run dev
# Health check: http://localhost:3000/api/health
```

### Start Frontend Development Server (Port 5173)
```powershell
Set-Location frontend
npm run dev
# Web application: http://127.0.0.1:5173
```

The dashboard uses the backend's authenticated Server-Sent Events stream and refreshes automatically after collector ingestion and analysis. The optional periodic refresh selector remains available as a fallback. Both services can be started together for local development:

```powershell
# Terminal 1
Set-Location C:\path\to\soc-lite\backend
npm start

# Terminal 2
Set-Location C:\path\to\soc-lite\frontend
npm run dev

# Terminal 3
Invoke-RestMethod -Uri 'http://127.0.0.1:3000/api/health'
Set-Location C:\path\to\soc-lite\collector
.\.venv\Scripts\python.exe .\agent.py
```

Never run `npm test` against public/development data. The backend test command recreates only the dedicated `soc_lite_test` PostgreSQL schema, applies the Prisma schema, seeds fixtures, and runs tests there. The legacy direct runner is intentionally opt-in via `npm run test:direct`.

---

## 7. Running Quality Assurance & Verification

### Backend Automated Test Suite
Executes all 20 test suites with 449 unit, integration, and security tests:
```bash
cd backend
npm test
```

### Frontend Code Quality & Linting
Validates all JavaScript and JSX with zero warnings:
```bash
cd frontend
npm run lint
```

### Frontend Production Build
Validates bundle compilation and route-level code splitting:
```bash
cd frontend
npm run build
```

### Prisma Schema Validation
```bash
cd backend
npx prisma validate
```

---

## 8. Available Report Types (PDF Security Reports)

1. **Security Overview Report:** Executive summary aggregating alerts, incidents, asset counts, threat intelligence, and severity distributions.
2. **Alert Activity Report:** Detailed alert listing with rule triggers and timestamps.
3. **Incident Investigation Report:** Comprehensive incident breakdown including linked alert counts and resolution metrics.
4. **Threat Intelligence Report:** IOC inventory, provider enrichment verdicts, and correlation breakdowns.
5. **Asset Inventory Report:** Monitored IT/OT asset directory filtered by criticality and environment.

---

## 9. Security & Data Integrity Features

- **Non-Cascading Audit Retention:** Deleting an Asset or Threat Indicator never deletes historical `AuditLog` evidence.
- **Sensitive Metadata Sanitization:** Passwords, password hashes, tokens, authorization headers, and API keys are automatically redacted (`[REDACTED]`) before persisting to audit logs.
- **Bounded Request Limits:** All queries enforce strict pagination limits (`limit <= 100`) to prevent Denial of Service.
- **Safe Fallback for Threat Providers:** Lookups gracefully report `NOT_CONFIGURED` without failing if external API keys are not supplied.

---

## 10. Known Limitations

- Real threat intelligence lookups require valid external API keys for VirusTotal, AbuseIPDB, or AlienVault OTX; without keys, mock or unconfigured status is returned.
- Single-instance Node.js process locking is used for detection engine serialization. Distributed worker queues (e.g. BullMQ / Redis) are recommended for enterprise cluster scaling.

## 11. Windows Event Log Collection

SOC Lite includes an optional, separately run Python collector in `collector/`. It reads real Windows Event Log records through the Windows Event Log API (`pywin32`) from `System`, `Application`, and, when permitted, `Security`. It does not generate events. The original XML returned by Windows is stored as the `RawLog`; normalized fields and the remaining Windows event data are stored on `Event`.

### Prepare the backend

The collector routes use the existing scoped `AgentToken` and `CollectorStatus` models. Windows event deduplication uses a transaction-scoped PostgreSQL advisory lock and a stable key in the existing `Event.metadata` JSON, so no schema change, migration, seed, or Prisma client regeneration is required for this feature. The configured database already exposes the collector models. The API listens on the configured `PORT`; the current local `.env` uses `3000`.

### Install and enroll on Windows

Use a supported 64-bit Python installation. Run these commands in PowerShell from the repository root:

```powershell
Set-Location .\collector
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .\config.example.json .\config.json
notepad .\config.json
```

Keep `api_url` at `http://127.0.0.1:3000/api` only when the collector and backend are on the same computer. For a remote backend, use an HTTPS URL with a valid certificate; the collector rejects non-loopback HTTP and does not disable certificate verification. Configure `channels`, `poll_interval_seconds` (5-3600), `batch_size` (1-200), and `start_from_beginning` in `config.json`. The default starts at the current end of each readable channel to avoid silently backfilling the entire existing log.

Start the backend, then enroll with an account that has the `ADMIN` role:

```powershell
python .\enroll_agent.py
```

Enrollment prompts for the administrator email and hidden password, creates one scoped/revocable agent token, and immediately protects it with Windows DPAPI for the current Windows user. The human JWT is held only in process memory and is not written to disk or printed. Restrict access to `token.dpapi` and `checkpoints.json` to the collector account. DPAPI-protected tokens can only be decrypted by the same Windows user profile on that computer. The administrator can revoke the credential through `DELETE /api/collectors/tokens/:id`.

Run the collector as that same Windows user:

```powershell
python .\agent.py
```

It checks in every polling cycle and on `Ctrl+C` stops between requests. To relocate configuration, checkpoint, or token files, set `SOC_LITE_COLLECTOR_CONFIG`, `SOC_LITE_COLLECTOR_STATE`, or `SOC_LITE_COLLECTOR_TOKEN_FILE` before starting it.

### Permissions and delivery behavior

The current process can read `System` and `Application` on this machine. Access to `Security` was not available during implementation verification. Keep the Security channel configured only when the chosen collector account already has read permission; where required, grant that account membership in Windows' built-in **Event Log Readers** group under your normal administrative change process. This grants read access and does not disable controls or change audit policy. Existing audit policy determines which event IDs are present; the collector does not enable auditing or manufacture records.

Each channel has a durable local record-ID checkpoint, atomically replaced on disk after each server-acknowledged sub-batch. Delivery is at-least-once while source records remain in Windows: retries and restarts can resend an unacknowledged batch, while a transaction-scoped PostgreSQL advisory lock and stable key in `Event.metadata` make those retries idempotent. If the Windows log is cleared or retention overwrites records while the collector is offline, those removed records cannot be recovered; the agent reports a record-ID reset and resumes from retained records. Back up the checkpoint file along with the collector configuration. The agent retries network errors, HTTP 429, and server errors with bounded exponential delay, does not advance checkpoints on rejection, and records only fixed, sanitized error descriptions in collector status. Each batch is bounded below the backend request-size limit.

`Security` access denial, missing channels, event parse failures, and backend delivery errors appear on the **Collectors** page. An inaccessible channel is retried; its initialization checkpoint is set to the current end once it first becomes readable unless `start_from_beginning` is enabled. No collector credential is returned by the status API or displayed in the UI.

### Verify genuine collection

1. Start the backend on port `3000` and the frontend on port `5173`; sign in as an authorized operator.
2. Enroll and start the collector. The **Collectors** page should show its host, configured channels, check-in time, and `Healthy` state. A missing Security permission is reported rather than bypassed.
3. Wait for a genuine new event from normal OS/application activity in a readable channel. Do not use fixture tests or synthetic event-writing commands as evidence of live collection.
4. Confirm the collector's `Last event` and `Events` count update. Open **Logs**, select the normalized event, and inspect its raw-log relation for Windows XML and the event metadata (`eventId`, `eventRecordId`, `provider`, `channel`, and `details`). `WINDOWS_FAILED_LOGON` only alerts after the configured threshold of real 4625 events with usable host and account values; 4624 is normalized as a successful logon but is not considered suspicious by itself.

For a read-only PostgreSQL check, connect to the configured database and run:

```sql
SELECT e."timestamp", e."eventType", e."hostname", e."metadata", r."source", r."rawContent"
FROM events AS e
JOIN raw_logs AS r ON r.id = e."rawLogId"
WHERE e."eventType" LIKE 'windows_%'
ORDER BY e."timestamp" DESC
LIMIT 10;
```

The collector tests in `collector/test_collector.py` use a clearly labeled fixed XML fixture and mocked HTTP responses; they are not live collection tests. Live verification requires a Windows machine with channel access, the backend and PostgreSQL running, the existing collector models available, and a real event arriving after the selected checkpoint. This environment can read genuine `System` and `Application` records; each ingestion result still needs to be verified against PostgreSQL and the UI.