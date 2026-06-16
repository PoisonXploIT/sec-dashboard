"""Sec-Dashboard configuration — tool registry and settings."""
import os
import shutil
import socket
import ssl
import subprocess
import asyncio
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = DATA_DIR / "results"
DB_PATH = DATA_DIR / "sec.db"
WORDLISTS_DIR = BASE_DIR / "backend" / "wordlists"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── Tool registry ──────────────────────────────────────────────
TOOLS = {
    # ─── Network Recon ───
    "port_scanner": {
        "name": "Port Scanner",
        "category": "Network Recon",
        "description": "Fast TCP port scanner with service detection",
        "icon": ">_",
        "timeout": 120,
    },
    "dns_recon": {
        "name": "DNS Recon",
        "category": "Network Recon",
        "description": "DNS records enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)",
        "icon": "NS",
        "timeout": 30,
    },
    "subdomain_enum": {
        "name": "Subdomain Enum",
        "category": "Network Recon",
        "description": "Subdomain discovery via DNS brute-force",
        "icon": "[]",
        "timeout": 120,
    },
    "http_probe": {
        "name": "HTTP Probe",
        "category": "Network Recon",
        "description": "HTTP/HTTPS probing with tech detection and response analysis",
        "icon": ">>",
        "timeout": 30,
    },
    "whois_lookup": {
        "name": "Whois Lookup",
        "category": "Network Recon",
        "description": "Domain WHOIS registration information",
        "icon": "??",
        "timeout": 15,
    },
    "ping_sweep": {
        "name": "Ping Sweep",
        "category": "Network Recon",
        "description": "ICMP reachability check for hosts",
        "icon": "..",
        "timeout": 60,
    },
    "traceroute": {
        "name": "Traceroute",
        "category": "Network Recon",
        "description": "Network path tracing to target",
        "icon": "->",
        "timeout": 60,
    },
    "ssl_analyzer": {
        "name": "SSL/TLS Analyzer",
        "category": "Network Recon",
        "description": "SSL/TLS certificate and cipher analysis",
        "icon": "##",
        "timeout": 15,
    },
    # ─── Web Security ───
    "header_analyzer": {
        "name": "Header Analyzer",
        "category": "Web Security",
        "description": "HTTP security headers audit (CSP, HSTS, X-Frame, etc.)",
        "icon": "{}",
        "timeout": 15,
    },
    "dir_fuzzer": {
        "name": "Directory Fuzzer",
        "category": "Web Security",
        "description": "Web directory and file brute-force discovery",
        "icon": "//",
        "timeout": 180,
    },
    "sqli_scanner": {
        "name": "SQLi Scanner",
        "category": "Web Security",
        "description": "Basic SQL injection detection via error-based and boolean-based tests",
        "icon": "';",
        "timeout": 120,
    },
    "xss_scanner": {
        "name": "XSS Scanner",
        "category": "Web Security",
        "description": "Reflected XSS detection in URL parameters",
        "icon": "<>",
        "timeout": 60,
    },
    "cors_checker": {
        "name": "CORS Checker",
        "category": "Web Security",
        "description": "Cross-Origin Resource Sharing misconfiguration detection",
        "icon": "x+",
        "timeout": 15,
    },
    "tech_detector": {
        "name": "Tech Detector",
        "category": "Web Security",
        "description": "Web technology stack fingerprinting",
        "icon": "{}",
        "timeout": 15,
    },
    "csp_analyzer": {
        "name": "CSP Analyzer",
        "category": "Web Security",
        "description": "Content Security Policy strength analysis",
        "icon": "[!]",
        "timeout": 15,
    },
    "open_redirect": {
        "name": "Open Redirect",
        "category": "Web Security",
        "description": "Open redirect vulnerability detection in URL parameters",
        "icon": "->",
        "timeout": 30,
    },
    # ─── Vulnerability ───
    "cve_search": {
        "name": "CVE Search",
        "category": "Vulnerability",
        "description": "Search NIST NVD for CVEs by keyword or ID",
        "icon": "#!",
        "timeout": 30,
    },
    "hash_checker": {
        "name": "Hash Lookup",
        "category": "Vulnerability",
        "description": "File hash reputation check via VirusTotal / MalwareBazaar",
        "icon": "md",
        "timeout": 15,
    },
    "password_audit": {
        "name": "Password Audit",
        "category": "Vulnerability",
        "description": "Password strength analysis and breach database check",
        "icon": "**",
        "timeout": 15,
    },
    # ─── System ───
    "network_connections": {
        "name": "Net Connections",
        "category": "System",
        "description": "Active network connections and listening ports",
        "icon": "TCP",
        "timeout": 10,
    },
    "process_monitor": {
        "name": "Process Monitor",
        "category": "System",
        "description": "Running process analysis with network correlation",
        "icon": "ps",
        "timeout": 10,
    },
    "system_info": {
        "name": "System Info",
        "category": "System",
        "description": "OS, network interfaces, firewall, and security posture",
        "icon": "hw",
        "timeout": 10,
    },
}

CATEGORIES = ["Network Recon", "Web Security", "Vulnerability", "System"]

# ── Pipeline modes ─────────────────────────────────────────────
PIPELINES = {
    "fast": {
        "name": "Fast Scan",
        "description": "Quick recon + port scan (~1 min)",
        "icon": "",
        "phases": [
            {"name": "Recon", "tools": ["whois_lookup", "dns_recon", "http_probe"]},
            {"name": "Scan", "tools": ["port_scanner"]},
        ],
    },
    "deep": {
        "name": "Deep Scan",
        "description": "Full recon + web analysis (~3 min)",
        "icon": "",
        "phases": [
            {"name": "Recon", "tools": ["whois_lookup", "dns_recon", "subdomain_enum", "http_probe"]},
            {"name": "Scan", "tools": ["port_scanner", "ssl_analyzer"]},
            {"name": "Web", "tools": ["header_analyzer", "tech_detector", "dir_fuzzer"]},
        ],
    },
    "nuclear": {
        "name": "Nuclear Scan",
        "description": "Comprehensive security audit (~10 min)",
        "icon": "",
        "phases": [
            {"name": "Recon", "tools": ["whois_lookup", "dns_recon", "subdomain_enum", "http_probe"]},
            {"name": "Scan", "tools": ["port_scanner", "ssl_analyzer"]},
            {"name": "Web", "tools": ["header_analyzer", "tech_detector", "dir_fuzzer", "sqli_scanner", "xss_scanner", "cors_checker", "csp_analyzer", "open_redirect"]},
            {"name": "Vuln", "tools": ["cve_search", "password_audit"]},
            {"name": "System", "tools": ["network_connections", "process_monitor", "system_info"]},
        ],
    },
}
