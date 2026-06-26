"""Scanner — maps tool names to handlers and executes them."""
import asyncio
import time
import traceback
from typing import Callable, Any

from backend.config import TOOLS, SPECIAL_TOOLS
from backend.tools.network import (
    port_scanner, dns_recon, subdomain_enum, http_probe,
    whois_lookup, ping_sweep, traceroute, ssl_analyzer,
)
from backend.tools.web import (
    header_analyzer, dir_fuzzer, sqli_scanner, xss_scanner,
    cors_checker, tech_detector, csp_analyzer, open_redirect,
)
from backend.tools.vuln import cve_search, hash_checker, password_audit
from backend.tools.system import network_connections, process_monitor, system_info
from backend.tools.audit import ps_security_audit
from backend.tools.wifi import wifi_marauder_scan, m5stick_networks
from backend.tools.osint import asn_lookup, reverse_dns, ct_logs, shodan_lookup, ip_geolocation
from backend.tools.emailsec import dnssec_checker, email_security, http_methods, robots_analyzer, caa_checker

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
    # Web Security
    "header_analyzer": header_analyzer,
    "dir_fuzzer": dir_fuzzer,
    "sqli_scanner": sqli_scanner,
    "xss_scanner": xss_scanner,
    "cors_checker": cors_checker,
    "tech_detector": tech_detector,
    "csp_analyzer": csp_analyzer,
    "open_redirect": open_redirect,
    # Vulnerability
    "cve_search": cve_search,
    "hash_checker": hash_checker,
    "password_audit": password_audit,
    # System
    "network_connections": network_connections,
    "process_monitor": process_monitor,
    "system_info": system_info,
    # OSINT
    "asn_lookup": asn_lookup,
    "reverse_dns": reverse_dns,
    "ct_logs": ct_logs,
    "shodan_lookup": shodan_lookup,
    "ip_geolocation": ip_geolocation,
    # Email Security
    "dnssec_checker": dnssec_checker,
    "email_security": email_security,
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
        return {"error": f"Unknown tool: {tool_name}", "success": False}

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
        return {
            "tool": tool_name,
            "target": target,
            "success": True,
            "elapsed_seconds": elapsed,
            "result": result,
        }
    except asyncio.TimeoutError:
        elapsed = round(time.time() - start, 2)
        return {
            "tool": tool_name,
            "target": target,
            "success": False,
            "elapsed_seconds": elapsed,
            "error": f"Timed out after {timeout}s",
        }
    except Exception as e:
        elapsed = round(time.time() - start, 2)
        return {
            "tool": tool_name,
            "target": target,
            "success": False,
            "elapsed_seconds": elapsed,
            "error": str(e),
            "traceback": traceback.format_exc(),
        }


async def run_parallel(tools: list[str], target: str, **kwargs) -> list[dict]:
    """Run multiple tools in parallel."""
    tasks = [run_tool(t, target, **kwargs) for t in tools]
    return await asyncio.gather(*tasks)
