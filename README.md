# CyberWatch Mini-SIEM

[![CI](https://github.com/omerbenguigui/CyberWatch/actions/workflows/ci.yml/badge.svg)](https://github.com/omerbenguigui/CyberWatch/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-4e8cff)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-25d9e8)](https://fastapi.tiangolo.com/)

CyberWatch is a lightweight security monitoring platform that ingests structured events,
applies explainable detection rules, creates alerts, and presents the result in a responsive
SOC dashboard. It was built as a portfolio project to demonstrate Python backend engineering,
security fundamentals, API design, testing, and product-quality user experience.

![Animated CyberWatch product walkthrough](docs/images/cyberwatch-demo.gif)

[Watch the full HD walkthrough](docs/demo/cyberwatch-walkthrough.mp4) ·
[View the dashboard screenshot](docs/images/dashboard.png)

## Highlights

- FastAPI REST API with automatic OpenAPI documentation
- Real-time, rule-based detection for brute force, port scanning, and suspicious processes
- One-click safe attack simulations that generate synthetic telemetry only
- MITRE ATT&CK mappings for every bundled detection rule
- Interactive alert investigation with status transitions and analyst notes
- SQLite persistence with indexed, parameterized queries
- API-key protection for ingestion and alert-triage operations
- Responsive SOC dashboard with event and severity visualizations
- Batch event ingestion and alert deduplication cooldowns
- Synthetic demo-data generator (no real attack traffic required)
- 20 automated tests, 96% coverage, linting, security scanning, and GitHub Actions CI

## Architecture

```mermaid
flowchart LR
    A[Log producers] -->|JSON events| B[FastAPI ingestion]
    B --> C[(SQLite event store)]
    B --> D[Detection engine]
    D -->|Matched rules| E[(Alert store)]
    C --> F[SOC dashboard]
    E --> F
```

The detection engine intentionally uses transparent rules rather than a black-box score. Each
alert includes a rule ID, evidence, source, severity, and human-readable explanation.

## Detection rules

| Rule ID | Detection | Trigger | Severity | MITRE ATT&CK |
| --- | --- | --- | --- | --- |
| `CW-AUTH-001` | Brute-force attempt | 5 failed logins from one IP in 5 minutes | High | `T1110` Brute Force |
| `CW-NET-001` | Port scan | 10 distinct destination ports from one IP in 2 minutes | Critical | `T1046` Network Service Discovery |
| `CW-ENDPOINT-001` | Suspicious process | Command line matches risky script-execution indicators | Critical | `T1059.001` PowerShell |

Repeated alerts for the same rule and source are suppressed for ten minutes to reduce analyst
fatigue.

## Quick start

### Windows: one click

Install Python 3.11+ with the Python launcher or **Add Python to PATH**, then double-click
[`start_windows.bat`](start_windows.bat). It creates `.venv` if needed, installs the project
runtime dependencies, seeds an empty database, starts the server, and opens the dashboard in
the default browser automatically.
Internet access is required to install dependencies. Keep the console open; press Ctrl+C to stop.
If setup fails, the console stays open with the error. Existing environment variables are respected.
If port 8000 is busy, set `CYBERWATCH_PORT` to another port before running the launcher.

Demo generation is atomic and only runs when the database has no events. Running it again,
including two concurrent launches, preserves existing events and alerts instead of adding
another 42 events. It does not delete duplicates that were already present.

### Local Python setup

```bash
python -m venv .venv
```

Activate the virtual environment:

```bash
# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

Install and run:

```bash
pip install -e ".[dev]"
python -m scripts.generate_demo_data
uvicorn app.main:app --reload
```

Open:

- Dashboard: <http://localhost:8000>
- API docs: <http://localhost:8000/docs>
- Health check: <http://localhost:8000/api/health>

### Docker

```bash
export CYBERWATCH_API_KEY="replace-with-a-long-random-value"
docker compose up --build
```

On Windows PowerShell, set the variable with:

```powershell
$env:CYBERWATCH_API_KEY="replace-with-a-long-random-value"
docker compose up --build
```

## Ingest an event

The development API key is `dev-key-change-me`. It must be overridden in production.

```bash
curl -X POST http://localhost:8000/api/events \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-change-me" \
  -d '{
    "event_type": "login_failed",
    "source_ip": "203.0.113.42",
    "destination_ip": "10.0.0.5",
    "destination_port": 22,
    "username": "admin",
    "message": "Invalid password"
  }'
```

Supported event types are `login_success`, `login_failed`, `network_connection`,
`process_start`, `file_access`, and `firewall_block`.

## API overview

| Method | Endpoint | Protected | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/health` | No | Service health |
| `POST` | `/api/events` | API key | Ingest one event |
| `POST` | `/api/events/batch` | API key | Ingest up to 500 events |
| `GET` | `/api/events` | No | Search recent events |
| `GET` | `/api/alerts` | No | Filter recent alerts |
| `PATCH` | `/api/alerts/{id}/acknowledge` | API key | Triage an alert |
| `PATCH` | `/api/alerts/{id}` | API key | Update status and analyst note |
| `GET` | `/api/dashboard/summary` | No | Aggregated dashboard metrics |
| `POST` | `/api/demo/simulate/{scenario}` | Local demo only | Generate safe synthetic attack telemetry |

## Tests and quality checks

```bash
ruff check .
bandit -q -r app scripts
pytest
node --check app/static/app.js
python -m build
```

The test suite covers detection thresholds, time windows, duplicate suppression, authentication,
event ingestion, safe attack simulations, alert investigation updates, and dashboard aggregation.

## What I learned

Building CyberWatch strengthened my understanding of end-to-end backend development and
defensive-security workflows: turning raw telemetry into explainable detections, designing a
secure API, evolving a database schema safely, and presenting investigation context clearly to
an analyst. I also practiced automated testing, CI, packaging, Docker, and documenting technical
decisions so another developer can run and review the project quickly.

## Security decisions

- Mutating endpoints use a constant-time API-key comparison.
- SQL statements use parameters rather than string interpolation for user-controlled values.
- Production startup fails when the default development API key is still configured.
- Interactive attack simulations are disabled automatically in production mode.
- Batch size and field lengths are bounded to reduce accidental resource exhaustion.
- The Docker container runs as an unprivileged user.
- The CI workflow has read-only repository permissions.

This project is an educational defensive-security tool. The bundled generator creates only
synthetic events and does not perform network scanning or exploitation.

## Future improvements

- PostgreSQL and asynchronous event queues for higher throughput
- User accounts with role-based access control
- Sigma-compatible custom detection rules
- Email or Slack notifications
- PCAP and syslog collectors
- Multi-user case ownership and investigation timelines

## Author

**Omer Benguigui** — Computer Science student focused on software development and cybersecurity.
