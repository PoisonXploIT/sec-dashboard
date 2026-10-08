# Sec-Dashboard

Local-first security dashboard for reconnaissance, vulnerability assessment, and monitoring. 52 tools across 7 categories, multi-phase pipeline engine, real-time WebSocket updates, and export in JSON/PDF.

Built with FastAPI + vanilla JS. No cloud dependencies, no accounts — runs entirely on your machine.

---

## Features

**52 Security Tools** organized in 7 categories:

| Category | Tools |
|----------|-------|
| Network Recon | Port Scanner, DNS Recon, Subdomain Enum, HTTP Probe, Whois Lookup, Ping Sweep, Traceroute, SSL/TLS Analyzer, SSL Deep Analyzer, CAA Checker |
| Web Security | Header Analyzer, Directory Fuzzer, SQLi Scanner, XSS Scanner, CORS Checker, Tech Detector, CSP Analyzer, Open Redirect, Secret Leak Scan, Favicon Fingerprint, HTTP Methods, Robots.txt Analyzer |
| Vulnerability | CVE Search, CVE Correlation, Subdomain Takeover, Hash Lookup, Password Audit, ExploitDB Search, Vulners Search |
| System | Net Connections, Process Monitor, System Info, PS Security Audit, WiFi Marauder Scan, M5Stick Networks |
| OSINT | ASN/BGP Lookup, Reverse DNS, CT Logs, Shodan Lookup, IP Geolocation, Wayback URLs, DNSDumpster Enum, PublicWWW Search, URLScan Lookup, GreyNoise Lookup, Hunter Email Finder, Grep.app Code Search |
| Email Security | DNSSEC Checker, Email Security, DNS Zone Hygiene |
| RF Hardware | HackRF CFF Analyzer, WiFi 802.11 Pcap Analyzer |

**Special tools** (don't require a target domain/IP):
- **Hash Lookup**: input a file hash (MD5/SHA-1/SHA-256) to check reputation
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
│   ├── main.py          # FastAPI: rutas, WebSocket /ws, CORS
│   ├── config.py        # Definicion de las 52 herramientas y los pipelines
│   ├── scanner.py       # Ejecutor de herramientas (dispatcher)
│   ├── pipeline.py      # Motor de pipelines por fases
│   ├── report.py        # Informes JSON y PDF (fpdf2)
│   ├── models.py        # Esquema SQLite (data/sec.db)
│   ├── validators.py    # Validacion del objetivo / proteccion SSRF
│   ├── authguard.py     # Autenticacion por clave de API
│   ├── ratelimit.py     # Limites de peticiones
│   ├── triage.py        # Triage de hallazgos
│   ├── findings.py      # Modelo y normalizacion de hallazgos
│   ├── jev.py           # Clasificacion con Jev (TypeSafe)
│   ├── local_llm.py     # LLM local (:8099), solo loopback
│   ├── proxy.py         # TOR / SOCKS5
│   ├── splunk.py        # Auto-indexado en Splunk (REST)
│   ├── webhooks.py      # Discord / Slack / HTTP
│   ├── maintenance.py   # Tareas de mantenimiento
│   ├── applog.py        # Logging
│   ├── cli.py           # CLI
│   └── tools/           # Implementacion por familia
│       ├── network.py  web.py  vuln.py  system.py  osint.py
│       ├── emailsec.py  favicon.py  audit.py  wifi.py
│       └── pcap.py  rf.py  rf_parser.py
├── frontend/
│   └── index.html       # SPA en JavaScript puro (sin build, sin framework)
├── docs/
│   └── USER-GUIDE.md
├── tests/               # pytest
├── data/
│   └── sec.db           # SQLite (se crea sola)
├── Dockerfile  ·  docker-compose.yml  ·  start.bat
├── requirements.txt  ·  requirements-dev.txt  ·  ruff.toml  ·  pytest.ini
└── README.md
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Health check and version |
| GET | `/api/dashboard/stats` | Dashboard overview stats |
| GET | `/api/tools` | List all available tools |
| GET | `/api/stats` | Aggregate usage stats |
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
| GET | `/api/scans/{id}/export/csv` | Export scan as CSV |
| DELETE | `/api/scans/all` | Delete all scans |
| GET | `/api/pipelines` | List pipeline configurations |
| POST | `/api/pipelines` | Execute a pipeline |
| GET | `/api/pipelines/history` | Pipeline execution history |
| POST | `/api/pipelines/{id}/cancel` | Cancel a running pipeline |
| GET | `/api/pipelines/{id}/result` | Get pipeline result |
| GET | `/api/pipelines/{id}/export/json` | Export pipeline as JSON |
| GET | `/api/pipelines/{id}/export/pdf` | Export pipeline as PDF |
| GET | `/api/pipelines/{id}/export/csv` | Export pipeline as CSV |
| GET | `/api/pipelines/{id}/executive-pdf` | Executive summary PDF |
| GET | `/api/pipelines/compare` | Compare two pipeline runs |
| DELETE | `/api/pipelines/all` | Delete all pipeline runs |
| GET | `/api/jev` | AI layer status (Jev + local LLM) |
| GET | `/api/jev/query` | Query a verdict for a finding |
| POST | `/api/jev` | Classify findings with Jev |
| POST | `/api/jev/test` | Test the Jev connection |
| GET | `/api/llm` | Local LLM status (loopback only) |
| POST | `/api/llm` | Save local LLM settings |
| POST | `/api/llm/explain` | Explain a finding in plain language |
| POST | `/api/llm/test` | Test the local LLM endpoint |
| GET | `/api/proxy` | Proxy (TOR/SOCKS5) status |
| POST | `/api/proxy` | Start/stop the proxy |
| GET | `/api/proxy/tor-ip` | Current TOR exit IP |
| GET | `/api/proxy/tor-install` | Install TOR helper |
| POST | `/api/upload/cff` | Upload a HackRF .cff capture (offline analysis) |
| POST | `/api/upload/pcap` | Upload a WiFi .pcap capture (offline analysis) |
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

---

## Contacto

- Pagina: [sammideblas.com](https://sammideblas.com)
- Email: analista@sammideblas.com
