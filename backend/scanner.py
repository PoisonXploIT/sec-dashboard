"""Scanner — maps tool names to handlers and executes them."""
import asyncio
import time
from typing import Callable, Any

from backend.applog import get_logger

from backend.config import TOOLS, SPECIAL_TOOLS
from backend.findings import extract_findings, score_findings
from backend.tools.network import (
    port_scanner, dns_recon, subdomain_enum, http_probe,
    whois_lookup, ping_sweep, traceroute, ssl_analyzer,
    subdomain_takeover, ssl_deep_analyzer, dnsdumpster_enum,
)
from backend.tools.web import (
    header_analyzer, dir_fuzzer, sqli_scanner, xss_scanner,
    cors_checker, tech_detector, csp_analyzer, open_redirect,
    cve_correlation, secret_leak_scan, wayback_urls,
)
from backend.tools.favicon import favicon_fingerprint
from backend.tools.vuln import cve_search, exploitdb_search, hash_checker, password_audit
from backend.tools.system import network_connections, process_monitor, system_info
from backend.tools.audit import ps_security_audit
from backend.tools.wifi import wifi_marauder_scan, m5stick_networks
from backend.tools.osint import (
    asn_lookup, reverse_dns, ct_logs, shodan_lookup, ip_geolocation,
    publicwww_search, urlscan_lookup, greynoise_lookup, hunter_email_finder,
)
from backend.tools.emailsec import (
    dnssec_checker, email_security, dns_zone_hygiene,
    http_methods, robots_analyzer, caa_checker,
)

_log = get_logger("scanner")

# ── Tool → Handler mapping ─────────────────────────────────────
HANDLERS: dict[str, Callable] = {
    # Network Recon
    "port_scanner": port_scanner,
    "dns_recon": dns_recon,
    "subdomain_enum": subdomain_enum,
    "http_probe": http_probe,
    "whois_lookup": whois_lookup,
    "ping_sweep": ping_sweep,
    "traceroute": traceroute,
    "ssl_analyzer": ssl_analyzer,
    "ssl_deep_analyzer": ssl_deep_analyzer,
    # Web Security
    "header_analyzer": header_analyzer,
    "dir_fuzzer": dir_fuzzer,
    "sqli_scanner": sqli_scanner,
    "xss_scanner": xss_scanner,
    "cors_checker": cors_checker,
    "tech_detector": tech_detector,
    "csp_analyzer": csp_analyzer,
    "open_redirect": open_redirect,
    "secret_leak_scan": secret_leak_scan,
    "favicon_fingerprint": favicon_fingerprint,
    # Vulnerability
    "cve_search": cve_search,
    "cve_correlation": cve_correlation,
    "subdomain_takeover": subdomain_takeover,
    "exploitdb_search": exploitdb_search,
    "hash_checker": hash_checker,
    "password_audit": password_audit,
    # System
    "network_connections": network_connections,
    "process_monitor": process_monitor,
    "system_info": system_info,
    # OSINT
    "wayback_urls": wayback_urls,
    "asn_lookup": asn_lookup,
    "reverse_dns": reverse_dns,
    "ct_logs": ct_logs,
    "shodan_lookup": shodan_lookup,
    "ip_geolocation": ip_geolocation,
    "publicwww_search": publicwww_search,
    "urlscan_lookup": urlscan_lookup,
    "greynoise_lookup": greynoise_lookup,
    "hunter_email_finder": hunter_email_finder,
    "dnsdumpster_enum": dnsdumpster_enum,
    # Email Security
    "dnssec_checker": dnssec_checker,
    "email_security": email_security,
    "dns_zone_hygiene": dns_zone_hygiene,
    # Web Security (additional)
    "http_methods": http_methods,
    "robots_analyzer": robots_analyzer,
    # Network Recon (additional)
    "caa_checker": caa_checker,
    # Host Audit
    "ps_security_audit": ps_security_audit,
    # WiFi Hardware (M5Stick devices)
    "wifi_marauder_scan": wifi_marauder_scan,
    "m5stick_networks": m5stick_networks,
}


async def run_tool(tool_name: str, target: str, **kwargs) -> dict:
    """Run a single tool against a target.

    For special tools (hash_checker, password_audit, cve_search), the 'target'
    is actually the direct input (hash, password, keyword). For system tools,
    target is ignored.
    """
    if tool_name not in HANDLERS:
        return {"error": f"Unknown tool: {tool_name}", "success": False,
                "findings": [], "score": 0}

    handler = HANDLERS[tool_name]
    tool_config = TOOLS.get(tool_name, {})
    timeout = tool_config.get("timeout", 60)

    # System tools don't need a target (or use target as data param)
    # WiFi tools use target as the Flask app URL (not in system_tools)
    system_tools = {"network_connections", "process_monitor", "system_info", "ps_security_audit"}

    start = time.time()
    try:
        if tool_name in system_tools:
            result = await asyncio.wait_for(handler(**kwargs), timeout=timeout)
        else:
            result = await asyncio.wait_for(handler(target, **kwargs), timeout=timeout)
        elapsed = round(time.time() - start, 2)
        # Fase 0.4: normalized findings ride along with the human-readable
        # result; the UI keeps consuming `result` untouched.
        findings = extract_findings(tool_name, result, target)
        return {
            "tool": tool_name,
            "target": target,
            "success": True,
            "elapsed_seconds": elapsed,
            "result": result,
            "findings": [f.to_dict() for f in findings],
            "score": score_findings(findings),
        }
    except asyncio.TimeoutError:
        elapsed = round(time.time() - start, 2)
        return {
            "tool": tool_name,
            "target": target,
            "success": False,
            "elapsed_seconds": elapsed,
            "error": f"Timed out after {timeout}s",
            "findings": [],
            "score": 0,
        }
    except Exception as e:
        elapsed = round(time.time() - start, 2)
        # M1: log full traceback server-side, but never leak it to the client
        _log.exception("tool error tool=%s target=%s", tool_name, target)
        return {
            "tool": tool_name,
            "target": target,
            "success": False,
            "elapsed_seconds": elapsed,
            "error": str(e),
            "findings": [],
            "score": 0,
        }


async def run_parallel(tools: list[str], target: str, **kwargs) -> list[dict]:
    """Run multiple tools in parallel."""
    tasks = [run_tool(t, target, **kwargs) for t in tools]
    return await asyncio.gather(*tasks)
