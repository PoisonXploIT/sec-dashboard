# Sec-Dashboard

Security dashboard with 27 pure-Python tools for network reconnaissance, web security analysis, vulnerability assessment, OSINT, and system monitoring.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **27 Security Tools** -- Network recon, web security, vulnerability scanning, OSINT, system monitoring
- **3 Pipeline Modes** -- Fast (~1min), Deep (~3min), Nuclear (~10min) automated multi-phase scans
- **Real-time Updates** -- WebSocket-powered live scan progress
- **Formatted Results** -- Human-readable result visualization (not raw JSON dumps)
- **Export** -- JSON (Splunk-compatible) and PDF reports, per-scan or bulk
- **Proxy/TOR** -- Integrated SOCKS5 proxy support for anonymous scanning
- **OSINT** -- Passive recon via Shodan, Certificate Transparency, ASN/BGP, geolocation
- **Pure Python** -- No nmap, no external binaries required
- **Dark Theme UI** -- Modern interface with search, category filters, and built-in guide
- **SQLite Storage** -- Persistent target/scan/pipeline history

## Quick Start

```bash
git clone https://github.com/YOUR_USER/sec-dashboard.git
cd sec-dashboard
python -m venv .venv
source .venv/Scripts/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8444
# Open http://127.0.0.1:8444
```

## Tools (27)

### Network Recon (8)
Port Scanner, DNS Recon, Subdomain Enum, HTTP Probe, Whois Lookup, Ping Sweep, Traceroute, SSL/TLS Analyzer

### Web Security (8)
Header Analyzer, Directory Fuzzer, SQLi Scanner (GET+POST), XSS Scanner, CORS Checker, Tech Detector, CSP Analyzer, Open Redirect

### Vulnerability (3)
CVE Search (NIST NVD), Hash Lookup (MalwareBazaar), Password Audit (HIBP)

### System (3)
Net Connections, Process Monitor, System Info

### OSINT (5) -- Passive recon, no packets to target
ASN/BGP Lookup, Reverse DNS, CT Logs (subdomain discovery), Shodan Lookup (InternetDB), IP Geolocation

## Proxy / Anonymity

- **TOR**: SOCKS5 proxy on 127.0.0.1:9150 (TOR Browser) or 9050 (expert bundle)
- **SOCKS5/4**: Compatible with any VPN provider (Mullvad, NordVPN, etc.)
- **Cloudflare Tunnel**: `cloudflared tunnel --url http://localhost:8444` for public HTTPS access

## Export

- **JSON per scan/pipeline**: Splunk-compatible format with `event`, `timestamp`, `target`, `result`
- **JSON bulk**: Export all data for SIEM ingestion
- **PDF**: Formatted report with tables, grades, and raw JSON appendix

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Health check |
| GET | `/api/tools` | List all tools |
| POST | `/api/tools/{id}/run` | Run a tool |
| GET/POST | `/api/targets` | CRUD targets |
| GET/POST | `/api/scans` | CRUD scans |
| GET | `/api/scans/{id}/export/json` | Export scan JSON |
| GET | `/api/scans/{id}/export/pdf` | Export scan PDF |
| POST | `/api/pipelines` | Start pipeline |
| GET | `/api/pipelines/history` | Pipeline history |
| GET | `/api/export/all/json` | Bulk export |
| GET/POST | `/api/proxy` | Proxy config |
| GET | `/api/proxy/tor-ip` | Verify TOR exit IP |
| WS | `/ws` | Real-time events |

## Architecture

```
sec-dashboard/
├── backend/
│   ├── main.py          # FastAPI + REST + WebSocket
│   ├── config.py        # Tool registry + pipelines
│   ├── scanner.py       # Tool dispatcher
│   ├── pipeline.py      # Multi-phase engine
│   ├── models.py        # SQLite models
│   ├── report.py        # JSON/PDF report generator
│   ├── proxy.py         # TOR/SOCKS5 proxy config
│   └── tools/
│       ├── network.py   # 8 network tools
│       ├── web.py       # 8 web security tools
│       ├── vuln.py      # 3 vulnerability tools
│       ├── system.py    # 3 system tools
│       └── osint.py     # 5 OSINT tools
├── frontend/
│   └── index.html       # Single-file SPA
├── requirements.txt
└── README.md
```

## Deployment

### Local
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8444
```

### Cloudflare Tunnel (free, no account needed)
```bash
cloudflared tunnel --url http://localhost:8444
```

### VPS
```bash
pip install -r requirements.txt
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8444
```

## Requirements

- Python 3.11+
- No external binaries
- ~50MB disk space

## License

MIT
