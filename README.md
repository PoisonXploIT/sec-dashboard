# Sec-Dashboard

A lightweight, pure-Python security dashboard with 22 built-in tools for network reconnaissance, web security analysis, vulnerability assessment, and system monitoring.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **22 Security Tools** — Network recon, web security, vulnerability scanning, system monitoring
- **3 Pipeline Modes** — Fast (~1min), Deep (~3min), Nuclear (~10min) automated multi-phase scans
- **Real-time Updates** — WebSocket-powered live scan progress
- **Formatted Results** — Beautiful, human-readable result visualization (not raw JSON dumps)
- **Pure Python** — No nmap, no external binaries required. Just Python + pip
- **Dark Theme UI** — Modern GitHub-inspired interface with search and category filters
- **SQLite Storage** — Persistent target/scan/pipeline history with zero config
- **Windows Compatible** — All tools work on Windows without admin privileges

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USER/sec-dashboard.git
cd sec-dashboard

# Setup
python -m venv .venv
source .venv/Scripts/activate # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8444

# Open http://127.0.0.1:8444
```

## Tools

### Network Recon (8 tools)
| Tool | Description |
|------|-------------|
| Port Scanner | Fast async TCP port scanner with service detection |
| DNS Recon | DNS records enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA) |
| Subdomain Enum | Subdomain discovery via DNS brute-force |
| HTTP Probe | HTTP/HTTPS probing with tech detection |
| Whois Lookup | Domain WHOIS registration information |
| Ping Sweep | ICMP reachability check |
| Traceroute | Network path tracing |
| SSL/TLS Analyzer | Certificate and cipher analysis |

### Web Security (8 tools)
| Tool | Description |
|------|-------------|
| Header Analyzer | HTTP security headers audit with grading |
| Directory Fuzzer | Web directory brute-force discovery |
| SQLi Scanner | SQL injection detection (error-based + boolean-based) |
| XSS Scanner | Reflected XSS detection |
| CORS Checker | CORS misconfiguration detection |
| Tech Detector | Web technology stack fingerprinting |
| CSP Analyzer | Content Security Policy strength analysis |
| ↩ Open Redirect | Open redirect vulnerability detection |

### Vulnerability (3 tools)
| Tool | Description |
|------|-------------|
| CVE Search | NIST NVD search by keyword or CVE ID |
| Hash Lookup | File hash reputation (MalwareBazaar + VirusTotal) |
| Password Audit | Password strength + Have I Been Pwned check |

### System (3 tools)
| Tool | Description |
|------|-------------|
| Net Connections | Active connections and listening ports |
| Process Monitor | Running processes with network correlation |
| System Info | OS, network, firewall, security posture |

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Health check |
| `/api/tools` | GET | List all tools |
| `/api/tools/{id}/run` | POST | Run a tool |
| `/api/targets` | GET/POST | List/create targets |
| `/api/targets/{id}` | DELETE | Delete target |
| `/api/scans` | GET/POST | List/create scans |
| `/api/pipelines` | GET/POST | List/start pipelines |
| `/api/pipelines/history` | GET | Pipeline history |
| `/api/pipelines/{id}/result` | GET | Pipeline result |
| `/api/reset` | DELETE | Reset all data |
| `/ws` | WebSocket | Real-time events |

## Architecture

```
sec-dashboard/
 backend/
 main.py # FastAPI app + REST API + WebSocket
 config.py # Tool registry + pipeline definitions
 scanner.py # Tool dispatcher with timeout handling
 pipeline.py # Multi-phase pipeline engine
 models.py # SQLite models (aiosqlite)
 tools/
 network.py # Network recon tools
 web.py # Web security tools
 vuln.py # Vulnerability tools
 system.py # System monitoring tools
 frontend/
 index.html # Single-file SPA (inline CSS/JS)
 data/ # SQLite DB + results (gitignored)
 requirements.txt
 .gitignore
 README.md
```

## Pipeline Modes

| Mode | Phases | Duration |
|------|--------|----------|
| **Fast** | Recon → Scan | ~1 min |
| **Deep** | Recon → Scan → Web | ~3 min |
| **Nuclear** | Recon → Scan → Web → Vuln → System | ~10 min |

## Optional API Keys

Set these environment variables for enhanced functionality:

```bash
# VirusTotal hash lookups
export VIRUSTOTAL_API_KEY=your_key

# That's it! All other tools work without API keys.
```

## Requirements

- Python 3.11+
- No external binaries (no nmap, no whois CLI, etc.)
- ~50MB disk space

## License

MIT License — use it however you want.
