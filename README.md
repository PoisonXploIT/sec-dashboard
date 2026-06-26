# Sec-Dashboard

Local-first security dashboard for reconnaissance, vulnerability assessment, and monitoring. 35 tools across 6 categories, multi-phase pipeline engine, real-time WebSocket updates, and export in JSON/PDF.

Built with FastAPI + vanilla JS. No cloud dependencies, no accounts — runs entirely on your machine.

---

## Features

**35 Security Tools** organized in 6 categories:

| Category | Tools |
|----------|-------|
| Network Recon | Port Scanner, DNS Recon, Subdomain Enum, HTTP Probe, Whois Lookup, Ping Sweep, Traceroute, SSL Analyzer, CAA Checker |
| Web Security | Header Analyzer, Dir Fuzzer, SQLi Scanner, XSS Scanner, CORS Checker, CSP Analyzer, Tech Detector, Open Redirect, HTTP Methods, Robots.txt Analyzer |
| Vulnerability | CVE Search, Hash Checker, Password Audit |
| System | Network Connections, Process Monitor, System Info, PS Security Audit, WiFi Marauder Scan, M5Stick Networks |
| OSINT | ASN Lookup, Reverse DNS, Certificate Transparency, Shodan Lookup, IP Geolocation |
| Email Security | DNSSEC Checker, Email Security (SPF/DKIM/DMARC) |

**Special tools** (don't require a target domain/IP):
- **Hash Checker**: input a file hash (MD5/SHA-1/SHA-256) to check reputation
- **Password Audit**: input a password to check strength and breach status
- **CVE Search**: input a keyword or CVE ID to search NIST NVD
- **System tools**: run on the local machine, no target needed
- **PS Security Audit**: full enterprise audit via PowerShell (Windows only, requires [Auditing_with_PowerShell](https://github.com/PoisonXploIT/Auditing_with_PowerShell) cloned locally)
- **WiFi Marauder Scan**: poll WiFi scan data from [wifi-marauder-viewer](https://github.com/PoisonXploIT/wifi-marauder-viewer) Flask app (M5StickC + Marauder firmware)
- **M5Stick Networks**: poll WiFi networks + clients from [Visualizacion_extendida_M5StickPlus2](https://github.com/PoisonXploIT/Visualizacion_extendida_M5StickPlus2) Flask app (M5Stick Plus 2 + Evil-M5Project firmware)

**Pipeline Engine** — Multi-phase automated scans:
- **Fast** (4 tools) — Quick recon + port scan
- **Deep** (14 tools) — Full recon + web + OSINT
- **Nuclear** (20 tools) — Comprehensive security audit

**Additional features:**
- Real-time WebSocket updates during scans
- Export individual scans or full history as JSON (Splunk/SIEM compatible) or PDF
- TOR/SOCKS5 proxy integration
- Target management with persistent scan history
- Dark theme responsive UI
- Built-in integrated guide and API reference
- Cancel running scans and pipelines
- Webhook notifications (Discord, Slack, generic HTTP)
- Splunk integration with auto-indexing via REST API — scan metadata always indexed; rich JSON tools (PS Audit, WiFi scans) export full results with custom sourcetypes (`powershell:audit`, `wifi:marauder`, `m5stick:networks`)
- SSRF protection in remote mode (blocks private/loopback/metadata IPs)
- Search and pagination in scan history
- Pipeline results with per-tool formatted output
- Favicon and search bar icon

---

## Quick Start

```bash
# Clone
git clone https://github.com/PoisonXploIT/sec-dashboard.git
cd sec-dashboard

# Install dependencies
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run
uvicorn backend.main:app --host 127.0.0.1 --port 8444
```

Open http://127.0.0.1:8444 in your browser.

---

## Architecture

```
sec-dashboard/
├── backend/
│   ├── main.py          # FastAPI app, routes, WebSocket
│   ├── config.py        # Tool definitions, pipeline configs, categories
│   ├── scanner.py       # Tool dispatcher and executor
│   ├── pipeline.py      # Multi-phase pipeline engine
│   ├── report.py        # JSON and PDF report generators
│   ├── proxy.py         # TOR/SOCKS5 proxy management
│   ├── models.py        # SQLite schema
│   ├── validators.py    # SSRF protection / target validation
│   ├── webhooks.py      # Discord/Slack/generic webhook notifications
│   ├── splunk.py        # Splunk REST API auto-indexing
│   └── tools/
│       ├── network.py   # Port scanner, DNS, subdomain, SSL, etc.
│       ├── web.py       # Headers, tech detection, SQLi, XSS, etc.
│       ├── vuln.py      # CVE search, hash checker, password audit
│       ├── system.py    # Network connections, processes, system info
│       └── osint.py     # ASN, reverse DNS, CT logs, Shodan, geolocation
├── frontend/
│   ├── index.html       # Single-page application (vanilla JS)
│   └── static/          # Icons, assets
├── data/
│   └── sec.db           # SQLite database (auto-created)
├── requirements.txt
└── README.md
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Health check and version |
| GET | `/api/dashboard/stats` | Dashboard overview stats |
| GET | `/api/tools` | List all available tools |
| POST | `/api/tools/{id}/run` | Run a single tool |
| GET | `/api/targets` | List targets |
| POST | `/api/targets` | Create target (SSRF-validated in remote mode) |
| DELETE | `/api/targets/{id}` | Delete target and its scans |
| GET | `/api/scans` | List scans (supports `?offset=0&limit=50&target_id=N`) |
| POST | `/api/scans` | Create and execute a scan |
| DELETE | `/api/scans/{id}` | Delete a scan |
| POST | `/api/scans/{id}/cancel` | Cancel a running scan |
| GET | `/api/scans/{id}/export/json` | Export scan as JSON |
| GET | `/api/scans/{id}/export/pdf` | Export scan as PDF |
| GET | `/api/pipelines` | List pipeline configurations |
| POST | `/api/pipelines` | Execute a pipeline |
| GET | `/api/pipelines/history` | Pipeline execution history |
| POST | `/api/pipelines/{id}/cancel` | Cancel a running pipeline |
| GET | `/api/pipelines/{id}/result` | Get pipeline result |
| GET | `/api/pipelines/{id}/export/json` | Export pipeline as JSON |
| GET | `/api/pipelines/{id}/export/pdf` | Export pipeline as PDF |
| GET | `/api/webhooks` | List webhooks |
| POST | `/api/webhooks` | Create webhook |
| PUT | `/api/webhooks/{id}` | Update webhook |
| DELETE | `/api/webhooks/{id}` | Delete webhook |
| POST | `/api/webhooks/{id}/test` | Send test notification |
| GET | `/api/splunk` | Get Splunk config (password masked) |
| POST | `/api/splunk` | Save Splunk config |
| POST | `/api/splunk/test` | Test Splunk connection + send test event |
| POST | `/api/splunk/export-all` | Bulk export all scans/pipelines to Splunk |
| GET | `/api/export/all/json` | Bulk JSON export |
| GET | `/api/export/all/pdf` | Bulk PDF report |
| WS | `/ws` | Real-time scan events |
| DELETE | `/api/reset?confirm=true` | Reset all data (requires confirmation) |

---

## Deployment

### Option 1: VPS + Cloudflare

Deploy the backend on a VPS and use Cloudflare as DNS/proxy:

```bash
# On your VPS
git clone https://github.com/PoisonXploIT/sec-dashboard.git
cd sec-dashboard
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8444
```

Point `api.yourdomain.com` to your VPS IP in Cloudflare DNS. Enable proxy for SSL.

### Option 2: Docker

```bash
docker build -t sec-dashboard .
docker run -p 8444:8444 sec-dashboard
```

### Option 3: Local only

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8444
```

---

## Tech Stack

- **Backend:** Python 3.11+, FastAPI, aiosqlite, aiohttp
- **Frontend:** Vanilla JS, HTML5, CSS3 (no framework)
- **Database:** SQLite (zero config)
- **Reports:** fpdf2 (PDF), native JSON
- **Real-time:** WebSocket (FastAPI native)
- **Proxy:** aiohttp-socks (TOR/SOCKS5)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
