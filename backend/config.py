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
    # -- OSINT (Passive) --
    "asn_lookup": {
        "name": "ASN/BGP Lookup",
        "category": "OSINT",
        "description": "ASN, BGP prefix, and network operator identification",
        "icon": "AS",
        "timeout": 15,
    },
    "reverse_dns": {
        "name": "Reverse DNS",
        "category": "OSINT",
        "description": "PTR records and reverse DNS chain for IP addresses",
        "icon": "rD",
        "timeout": 10,
    },
    "ct_logs": {
        "name": "CT Logs",
        "category": "OSINT",
        "description": "Certificate Transparency log search -- discovers subdomains via SSL certs",
        "icon": "CT",
        "timeout": 20,
    },
    "shodan_lookup": {
        "name": "Shodan Lookup",
        "category": "OSINT",
        "description": "Shodan internet intelligence -- ports, vulns, services (free InternetDB)",
        "icon": "Sh",
        "timeout": 15,
    },
    "ip_geolocation": {
        "name": "IP Geolocation",
        "category": "OSINT",
        "description": "IP geolocation, ISP, org, proxy/hosting detection",
        "icon": "Gp",
        "timeout": 10,
    },
    # ─── Email Security ───
    "dnssec_checker": {
        "name": "DNSSEC Checker",
        "category": "Email Security",
        "description": "Verifies DNSSEC status and chain of trust for a domain",
        "icon": "DS",
        "timeout": 15,
    },
    "email_security": {
        "name": "Email Security",
        "category": "Email Security",
        "description": "SPF, DKIM, and DMARC record analysis for a domain",
        "icon": "EM",
        "timeout": 15,
    },
    "http_methods": {
        "name": "HTTP Methods",
        "category": "Web Security",
        "description": "Checks which HTTP methods are allowed (PUT, DELETE, TRACE, etc.)",
        "icon": "HM",
        "timeout": 15,
    },
    "robots_analyzer": {
        "name": "Robots.txt Analyzer",
        "category": "Web Security",
        "description": "Analyzes robots.txt for sensitive paths and misconfigurations",
        "icon": "RB",
        "timeout": 10,
    },
    "caa_checker": {
        "name": "CAA Checker",
        "category": "Network Recon",
        "description": "Checks CAA records -- which CAs can issue certificates",
        "icon": "CA",
        "timeout": 10,
    },
    # ─── Host Audit ───
    "ps_security_audit": {
        "name": "PS Security Audit",
        "category": "System",
        "description": "Full enterprise security audit via PowerShell (10 modules: system, users, processes, network, logs, files, registry, LOLBAS, drivers, hardware)",
        "icon": "PS",
        "timeout": 600,
    },
    # ─── WiFi Hardware (M5Stick devices) ───
    "wifi_marauder_scan": {
        "name": "WiFi Marauder Scan",
        "category": "System",
        "description": "Poll WiFi scan data from M5StickC Marauder viewer (networks, RSSI, BSSID, ESSID)",
        "icon": "WF",
        "timeout": 30,
    },
    "m5stick_networks": {
        "name": "M5Stick Networks",
        "category": "System",
        "description": "Poll WiFi networks + clients from M5Stick Plus 2 Evil-M5Project viewer",
        "icon": "M5",
        "timeout": 30,
    },
}

CATEGORIES = ["Network Recon", "Web Security", "Vulnerability", "System", "OSINT", "Email Security"]

# ── Special tools (don't use target domain/IP, need custom input) ──
SPECIAL_TOOLS = {
    "hash_checker": {
        "input_label": "Hash (MD5 / SHA-1 / SHA-256)",
        "input_placeholder": "e.g. d41d8cd98f00b204e9800998ecf8427e",
        "input_type": "text",
    },
    "password_audit": {
        "input_label": "Password to analyze",
        "input_placeholder": "Type a password to check strength + breach status",
        "input_type": "password",
    },
    "cve_search": {
        "input_label": "Keyword or CVE ID",
        "input_placeholder": "e.g. Apache 2.4 or CVE-2024-12345",
        "input_type": "text",
    },
    "network_connections": {
        "input_label": None,
        "input_placeholder": None,
        "input_type": "none",
    },
    "process_monitor": {
        "input_label": None,
        "input_placeholder": None,
        "input_type": "none",
    },
    "system_info": {
        "input_label": None,
        "input_placeholder": None,
        "input_type": "none",
    },
    "ps_security_audit": {
        "input_label": None,
        "input_placeholder": None,
        "input_type": "none",
    },
    "wifi_marauder_scan": {
        "input_label": "Marauder Viewer URL",
        "input_placeholder": "http://127.0.0.1:5000",
        "input_type": "text",
    },
    "m5stick_networks": {
        "input_label": "M5Stick Viewer URL",
        "input_placeholder": "http://127.0.0.1:5000",
        "input_type": "text",
    },
}

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
        "description": "Full recon + web + OSINT (~5 min)",
        "icon": "",
        "phases": [
            {"name": "Recon", "tools": ["whois_lookup", "dns_recon", "subdomain_enum", "http_probe"]},
            {"name": "Scan", "tools": ["port_scanner", "ssl_analyzer"]},
            {"name": "Web", "tools": ["header_analyzer", "tech_detector", "dir_fuzzer", "cors_checker", "csp_analyzer"]},
            {"name": "OSINT", "tools": ["reverse_dns", "ct_logs", "ip_geolocation"]},
        ],
    },
    "nuclear": {
        "name": "Nuclear Scan",
        "description": "Comprehensive security audit (~7 min)",
        "icon": "",
        "phases": [
            {"name": "Recon", "tools": ["whois_lookup", "dns_recon", "subdomain_enum", "http_probe", "caa_checker"]},
            {"name": "Scan", "tools": ["port_scanner", "ssl_analyzer"]},
            {"name": "Web", "tools": ["header_analyzer", "tech_detector", "dir_fuzzer", "sqli_scanner", "xss_scanner", "cors_checker", "csp_analyzer", "open_redirect", "http_methods", "robots_analyzer"]},
            {"name": "Vuln", "tools": ["cve_search"]},
            {"name": "OSINT", "tools": ["asn_lookup", "reverse_dns", "ct_logs", "shodan_lookup", "ip_geolocation"]},
            {"name": "Email", "tools": ["dnssec_checker", "email_security"]},
        ],
    },
}
