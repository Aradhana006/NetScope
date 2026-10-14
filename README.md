# NetScope — Network & DNS Diagnostic System

NetScope is a web-based network diagnostic platform that combines DNS analysis, connectivity testing, TCP port checks, HTTP/HTTPS analysis, and network performance measurements into a unified dashboard. It is built as a **Computer Networks academic project** to demonstrate how layered diagnostics (DNS → ICMP → TCP → HTTP) help explain why a site may be unreachable—without claiming that any single test proves the root cause.

## Objectives

- Analyze DNS records including A, AAAA, MX, NS, and CNAME.
- Measure network latency and packet loss (ping, with OS-specific parsing).
- Check TCP port reachability (initially 80 and 443).
- Verify HTTP/HTTPS availability, status codes, and response times.
- Generate rule-based health scores and troubleshooting suggestions.
- Maintain analysis history (SQLite) and generate PDF reports (ReportLab).

## Tech Stack

| Layer | Technology |
|--------|------------|
| Frontend | HTML5, CSS3, vanilla JavaScript |
| Charts | Chart.js (when results UI is wired) |
| Backend | Python 3, Flask |
| DNS | dnspython |
| Ping | OS `ping` via Python `subprocess` (argument list, no shell) |
| TCP | Python `socket` |
| HTTP(S) | `requests` |
| Database | SQLite (`sqlite3`) |
| PDF | ReportLab |

No React, Node.js, Docker, or heavy frameworks—run locally for demos.

## Project structure

```
NetScope/
├── app.py                 # Flask routes, validation, orchestration (not diagnostic logic)
├── requirements.txt       # Python dependencies
├── README.md
├── .gitignore
├── diagnostics/           # Independent diagnostic modules (team-parallel friendly)
│   ├── dns_check.py       # Member 1 — DNS
│   ├── connectivity.py    # Member 2 — ping / RTT / packet loss
│   ├── tcp_check.py       # Member 2 — TCP ports
│   ├── http_check.py      # Member 2 — HTTP/HTTPS
│   ├── traceroute_check.py# Member 2 — optional, later
│   └── diagnosis.py       # Member 2 — scoring & suggestions
├── database/
│   └── history.py         # SQLite schema & CRUD (later)
├── reports/
│   └── pdf_report.py      # ReportLab PDF (later)
├── templates/
│   └── index.html         # Dashboard shell
├── static/
│   ├── css/style.css
│   └── js/app.js
└── tests/
    └── test_api.py        # Automated tests (pytest)
```

### Why this layout?

- **`app.py`** only wires HTTP to your modules. That keeps Flask code small and lets each person test diagnostics from a Python shell or unit tests without starting the server.
- **`diagnostics/`** each file is one networking concept (DNS, ICMP, TCP, HTTP). Failures in one module should return structured errors, not crash the whole analysis.
- **`database/`** and **`reports/`** are separate so history and PDF work can land after core measurements work.
- **`static/`** and **`templates/`** are the dashboard Member 1 owns.

## Team responsibilities

| Member | Focus |
|--------|--------|
| **Member 1 (Aradhana S.)** | Flask API contract, input validation, orchestration, `dns_check.py`, frontend (HTML/CSS/JS), wiring dashboard to `POST /api/analyze` |
| **Member 2 (Akshaya T.)** | `connectivity.py`, `tcp_check.py`, `http_check.py`, `diagnosis.py`, later `history.py`, `pdf_report.py`, optional `traceroute_check.py` |

**Git workflow:** use feature branches (e.g. `feature/dns-module`, `feature/ping-tcp-http`) and merge via pull requests. Keep the JSON API contract stable on `main`.

## API design (planned)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | Dashboard |
| `GET` | `/api/health` | Health check (implemented) |
| `POST` | `/api/analyze` | Run full diagnostics (returns `id` when saved) |
| `GET` | `/api/history` | List past analyses (`?limit=20`) |
| `GET` | `/api/report/<id>` | Download PDF for analysis `id` |

### Request (analyze)

```json
{
  "target": "example.com"
}
```

### Response contract (each module uses the same error pattern)

Every submodule returns JSON-compatible data with:

- **`status`**: `"success"` | `"error"` | `"partial"` | `"skipped"`
- **`error`**: optional string when not successful (no stack traces to the client)

Example **shape** (values are illustrative, not fabricated measurements):

```json
{
  "target": "example.com",
  "timestamp": "2026-10-13T12:00:00Z",
  "dns": {
    "status": "success",
    "response_time_ms": null,
    "records": {
      "A": [],
      "AAAA": [],
      "MX": [],
      "NS": [],
      "CNAME": []
    },
    "error": null
  },
  "connectivity": {
    "status": "success",
    "reachable": null,
    "average_rtt_ms": null,
    "packet_loss_percent": null,
    "probes_sent": 0,
    "error": null
  },
  "tcp": {
    "status": "success",
    "ports": {},
    "error": null
  },
  "http": {
    "status": "success",
    "http": {},
    "https": {},
    "error": null
  },
  "diagnosis": {
    "health_score": null,
    "status": "Unknown",
    "suggestions": []
  }
}
```

Units: milliseconds for times, percent for packet loss. **`health_score`** is 0–100, documented as an educational heuristic in `diagnostics/diagnosis.py` (base 50, DNS ±35/±20, ping ±10, TCP 443 ±15, HTTPS ±20, thresholds 75/45 for Healthy/Degraded/Unavailable).

## Security and engineering rules

- Validate targets (hostname / IP format); reject empty or maliciously long input.
- Never pass user input through a shell; use `subprocess` with a list of arguments.
- Timeouts on all network operations; cap ping count and traceroute hops.
- One module failing must not stop others—wrap each call in `app.py` and merge partial results.
- Do not expose internal exceptions in API responses.
- Run locally for academic demo; do not deploy as a public open scanner.

## Setup (Windows or Linux)

### 1. Clone and enter the project

```bash
git clone https://github.com/<your-org>/NetScope.git
cd NetScope
```

### 2. Create a virtual environment

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

Open [http://127.0.0.1:5000/](http://127.0.0.1:5000/). The **System status** card should show **Backend online** if `/api/health` responds.

Alternative:

```bash
flask --app app run --debug
```

### 5. Run tests

```bash
pytest
```

## Implementation roadmap

### Phase 0 — Foundation (current)

- [x] Repository structure and module stubs
- [x] Flask dashboard + `GET /api/health`
- [x] Minimal frontend + health check in JavaScript
- [x] Pytest smoke tests

### Phase 1 — Member 1

1. [x] Target validation in `validators.py`.
2. [x] Implement `analyze_dns()` in `diagnostics/dns_check.py` with dnspython.
3. [x] Add `POST /api/analyze` (DNS live; other modules `skipped` until Member 2).
4. [x] Enable analyze form; render DNS table and summary in `app.js`.
5. [x] Tests: validators, DNS (mocked), analyze API (mocked + invalid input).

**Branch:** `feature/member1-dns-api`

### Phase 2 — Member 2

1. Implement `analyze_connectivity`, `analyze_tcp`, `analyze_http`.
2. Implement `build_diagnosis()` with documented scoring rules.
3. Wire modules into `POST /api/analyze` (Member 1 orchestrates; Member 2 owns module internals).
4. Add Chart.js for RTT / packet loss when data exists.
5. Tests for ping parsing (Windows vs Linux), socket timeouts, HTTP errors.

### Phase 3 — Persistence and reporting

1. `database/history.py` — save and list analyses.
2. `GET /api/history` and history UI section.
3. `reports/pdf_report.py` and `GET /api/report/<id>`.
4. Optional: `traceroute_check.py` with strict hop limits.

## Project status

**Foundation complete.** Diagnostic modules are stubbed with documented function signatures; analysis and history endpoints are not yet implemented.

## Team

- Aradhana S.
- Akshaya T.

## License

MIT — see [LICENSE](LICENSE).

## Scope disclaimer

NetScope is an educational troubleshooting tool. Results reflect observable measurements at run time. ICMP blocking, CDN behavior, and firewalls can make individual tests inconclusive— the diagnosis engine should say so explicitly.
