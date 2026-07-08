# FireGuard — System Guide

## What FireGuard Is

FireGuard is a **centralized endpoint firewall management system with integrated
host-based intrusion monitoring**. It does not replace Windows Defender Firewall —
it drives it. FireGuard adds a layer on top of Windows Firewall that gives an
administrator centralized policy control, endpoint visibility, security alerting,
and reporting, all through a **web-based management console**.

In plain terms: one admin, in one browser tab, can define firewall rules once and
push them out to many Windows machines, see which machines are online/offline,
get alerted to suspicious traffic patterns, and export activity reports — instead
of RDP-ing into every machine and running `netsh` by hand.

## Architecture

FireGuard is a **client-server system with two components**, not a single
monolithic app:

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│   FireGuard Server           │         │   FireGuard Agent             │
│   (app.py — Flask web app)   │◄───────►│   (agent.py — background      │
│                               │  HTTPS  │   process per endpoint)       │
│  - Web dashboard (browser)   │  Bearer │                                │
│  - Auth + roles              │  token  │  - Sends heartbeat (CPU/RAM/  │
│  - Firewall rule CRUD        │         │    connections/FW status)     │
│  - Traffic monitor (psutil)  │         │  - Polls for pending rules    │
│  - Alerting engine           │         │  - Applies rules via netsh    │
│  - Reports (PDF/CSV)         │         │  - Reports rule apply result  │
│  - Endpoint fleet management │         │                                │
└──────────────┬────────────────┘         └──────────────────────────────┘
               │
        ┌──────▼──────┐
        │  Database    │   SQL Server (localdb) locally,
        │  (SQL Server │   MySQL schema provided for cloud
        │   or MySQL)  │   hosting (PythonAnywhere, etc.)
        └─────────────┘
```

**Why split this way:** applying Windows Firewall rules (`netsh advfirewall`)
requires Administrator privileges. Rather than running the entire web console
elevated (a larger attack surface), only the small `agent.py` process runs with
elevated rights on each endpoint. The dashboard itself never needs admin rights.

## Component 1: The Server (`app.py`)

A Flask application that is the single source of truth and the only thing a
human interacts with directly.

**Auth & access control**
- Session-based login (`werkzeug` password hashing, `pbkdf2`/`scrypt`)
- Three roles: **Administrator**, **Security Analyst**, **Viewer** — enforced
  per-route via `@roles_required(...)`
- **Login attempt lockout:** 5 wrong passwords locks the account for 15 minutes
  (`failed_attempts`/`locked_until` columns on `users`, enforced in `/login`)
- **Two-Factor Authentication (TOTP):** optional per-user, self-service at
  `/account/security` — `pyotp` + `qrcode` generate a scannable secret for any
  authenticator app (Google Authenticator, Authy, etc.); once enabled, a correct
  password redirects to `/login/verify-2fa` instead of logging in directly, and
  only a valid 6-digit code completes the session (`totp_secret`/`totp_enabled`
  columns on `users`)
- A global `before_request` hook blocks any request from an IP that's in
  `blocked_ips` or matched by an active BLOCK rule, before it reaches any page

**Firewall rule management (`/rules`)**
- Admins create/edit/delete rules: name, IP (optional — blank = any), port,
  protocol (TCP/UDP), action (ALLOW/BLOCK), status (Active/Inactive)
- Rules can be applied live to Windows Firewall on the server machine itself
  (`apply_windows_firewall_rule`, gated by a `Live Mode` setting + admin check),
  or just recorded in the database ("Recorded Mode") for demo/testing without
  touching the OS firewall
- Rules can also be **pushed to remote endpoints** for the agent to apply

**Traffic monitoring & intrusion detection (background thread)**
Started by `start_monitor()` when the server boots. Every few seconds it
inspects live connections (via `psutil`) **on the machine running the server**
and runs three detectors:
| Detector | Trigger | Severity |
|---|---|---|
| Repeated Connection Attempts | > 5 new connections from same IP within 30s | WARNING |
| High Connection Count | > 100 total live connections system-wide | HIGH |
| Restricted Port Access | connection touches port 22/23/135/445/3389 | HIGH |

Each matched connection is also classified ALLOW/BLOCK against the active rule
set and logged to `traffic_logs`; BLOCKed IPs are auto-added to `blocked_ips`.

**Attack Simulator (`/simulate/attack`)**
A demo/testing feature — synthesizes a fake port scan + flood from a chosen IP
so alerting and auto-block behavior can be demonstrated without a real attacker.

**Alerts (`/alerts`)** — paginated view of all recorded alerts + currently
blocked IPs, with manual unblock.

**Reports (`/reports`)** — generates and downloads traffic activity as PDF
(`reportlab`) or CSV, and logs each generation to a `reports` table.

**Endpoint fleet management (`/endpoints`)**
- Register a new endpoint → generates a random Bearer token
  (`secrets.token_hex(20)`) the admin pastes into that machine's
  `agent_config.json`
- Shows each endpoint's status (Online/Offline/Warning), last seen, CPU%,
  memory%, connection count, firewall on/off — sourced from its latest
  heartbeat
- An endpoint is marked **Offline** automatically if no heartbeat has arrived
  in 90 seconds (`AGENT_OFFLINE_SECONDS`)
- Admin can select rules and **push** them to one endpoint or **push to all**
  online endpoints at once — this queues rows in
  `endpoint_rule_deployments` with status `Pending`

**Agent-facing API** (token-authenticated, not session-authenticated):
| Route | Called by agent to... |
|---|---|
| `POST /api/agent/heartbeat` | report CPU/mem/connections/firewall status |
| `GET /api/agent/rules` | poll for rules queued for this endpoint |
| `POST /api/agent/rule-result` | report success/failure of applying a rule |

## Component 2: The Agent (`agent.py`)

A small, dependency-light Python script meant to run continuously on **each
protected endpoint** (not the server). It is not a GUI — it's a headless loop.

On each cycle (default every 30s, `heartbeat_interval` in `agent_config.json`):
1. Collects CPU%, memory%, live connection count (`psutil`), whether Windows
   Firewall is on (`netsh advfirewall show allprofiles state`), IP, MAC address
2. POSTs that health snapshot to the server
3. GETs any pending rules queued for it, applies each via `netsh` (adds
   matching inbound rule, plus an outbound block rule if the action is BLOCK)
4. POSTs the result (success/failure + message) back to the server

Configuration lives in `agent_config.json` (created with a placeholder token
on first run — the admin must register the endpoint in the dashboard and paste
the real token in before the agent will authenticate).

> **Current limitation to know:** the agent only reports *health* metrics
> (CPU/mem/connection count/firewall on-off). The actual intrusion-detection
> heuristics (repeated connections, restricted ports, high connection count)
> currently run only against the **server's own traffic**, not each endpoint's.
> Extending real per-endpoint intrusion detection would mean running that same
> classification logic inside `agent.py` and reporting alerts back through a
> new endpoint (e.g. `/api/agent/alert`).

## Data Model

| Table | Purpose |
|---|---|
| `users` | login accounts + role |
| `firewall_rules` | the rule set (name, IP, port, protocol, action, status) |
| `blocked_ips` | IPs currently blocked, with reason |
| `traffic_logs` | every classified connection event |
| `alerts` | every raised alert (type, IP, description, time) |
| `reports` | record of generated PDF/CSV reports |
| `endpoints` | registered machines (hostname, token, status, last_seen, IP/MAC, version) |
| `endpoint_heartbeats` | time-series health snapshots per endpoint |
| `endpoint_rule_deployments` | queue + result of rules pushed to endpoints |

Two schema variants exist: SQL Server (`(localdb)\MSSQLLocalDB`, default) for
local development, and MySQL (`deploy/schema_mysql.sql`) for cloud hosting
(e.g. PythonAnywhere).

## Deployment Modes

- **Local / demo:** run `app.py` directly; SQL Server LocalDB; "Recorded Mode"
  (`apply_firewall_rules: false` in `fireguard_settings.json`) so no real
  Windows Firewall rules are touched — safe for demoing without admin rights.
- **Live Mode:** set `FIREGUARD_APPLY_FIREWALL=1` (or the settings file flag)
  and run as Administrator (`start_live_admin.ps1`) — rules are actually
  applied to Windows Defender Firewall via `netsh`.
- **Remote access:** `start_public_tunnel.bat` exposes the local server
  publicly (tunnel), and `deploy/` contains a `wsgi.py` + MySQL schema +
  `requirements.txt` for hosting the console on a cloud platform instead of a
  laptop.

## One-line description

> FireGuard is a centralized endpoint firewall management system with
> host-based intrusion monitoring on the management server and lightweight
> health monitoring on managed endpoints, enhancing Windows Defender Firewall
> through centralized policy deployment, endpoint visibility, alerting, and
> reporting — delivered as a web-based management console.
