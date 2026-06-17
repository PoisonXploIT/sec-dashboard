"""Report generator -- JSON and PDF export for scans and pipelines."""
import json
from datetime import datetime
from io import BytesIO
from typing import Any

from fpdf import FPDF


class ReportPDF(FPDF):
    """Custom PDF with sec-dashboard branding."""

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "Sec-Dashboard Report", align="L")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 12)
        self.set_fill_color(30, 30, 30)
        self.set_text_color(255, 255, 255)
        self.cell(0, 8, f"  {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(3)

    def kv_row(self, key: str, value: str):
        self.set_font("Helvetica", "B", 9)
        self.cell(50, 6, key, new_x="END")
        self.set_font("Helvetica", "", 9)
        self.multi_cell(0, 6, str(value)[:200], new_x="LMARGIN", new_y="NEXT")

    def add_json_block(self, data: Any, max_lines: int = 40):
        """Add formatted JSON block."""
        text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        lines = text.split("\n")[:max_lines]
        if len(text.split("\n")) > max_lines:
            lines.append(f"  ... ({len(text.split(chr(10)))} lines total)")
        self.set_font("Courier", "", 7)
        self.set_fill_color(245, 245, 245)
        for line in lines:
            safe = line.encode("latin-1", errors="replace").decode("latin-1")
            self.cell(0, 4, f"  {safe}", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)


def generate_scan_json(scan: dict, target: dict = None) -> str:
    """Generate JSON export for a single scan (Splunk-compatible)."""
    result_data = {}
    if scan.get("result"):
        try:
            result_data = json.loads(scan["result"])
        except (json.JSONDecodeError, TypeError):
            result_data = {"raw": scan["result"]}

    export = {
        "event": "sec_dashboard_scan",
        "timestamp": scan.get("started_at", datetime.utcnow().isoformat()),
        "scan_id": scan.get("id"),
        "tool": scan.get("tool"),
        "status": scan.get("status"),
        "target": {
            "id": target.get("id") if target else scan.get("target_id"),
            "name": target.get("name", "") if target else "",
            "host": target.get("host", "") if target else "",
        },
        "elapsed_seconds": result_data.get("elapsed_seconds"),
        "success": result_data.get("success"),
        "result": result_data.get("result", result_data),
    }
    return json.dumps(export, indent=2, ensure_ascii=False, default=str)


def generate_pipeline_json(pipeline: dict, target: dict = None) -> str:
    """Generate JSON export for a pipeline run (Splunk-compatible)."""
    result_data = {}
    if pipeline.get("result"):
        try:
            result_data = json.loads(pipeline["result"])
        except (json.JSONDecodeError, TypeError):
            result_data = {"raw": pipeline["result"]}

    export = {
        "event": "sec_dashboard_pipeline",
        "timestamp": pipeline.get("started_at", datetime.utcnow().isoformat()),
        "pipeline_id": pipeline.get("id"),
        "mode": pipeline.get("mode"),
        "status": pipeline.get("status"),
        "target": {
            "id": target.get("id") if target else pipeline.get("target_id"),
            "name": target.get("name", "") if target else "",
            "host": target.get("host", "") if target else "",
        },
        "elapsed_seconds": result_data.get("elapsed_seconds"),
        "total_tools": result_data.get("total_tools"),
        "phases": result_data.get("phases", {}),
    }
    return json.dumps(export, indent=2, ensure_ascii=False, default=str)


def generate_all_json(scans: list, pipelines: list, targets: list) -> str:
    """Generate bulk JSON export for all data (Splunk / SIEM ingestion)."""
    target_map = {t["id"]: t for t in targets}

    events = []
    for scan in scans:
        tgt = target_map.get(scan.get("target_id"))
        try:
            result_data = json.loads(scan.get("result", "{}"))
        except (json.JSONDecodeError, TypeError):
            result_data = {}

        events.append({
            "event": "sec_dashboard_scan",
            "timestamp": scan.get("started_at"),
            "scan_id": scan.get("id"),
            "tool": scan.get("tool"),
            "status": scan.get("status"),
            "target_name": tgt.get("name", "") if tgt else "",
            "target_host": tgt.get("host", "") if tgt else "",
            "success": result_data.get("success"),
            "elapsed_seconds": result_data.get("elapsed_seconds"),
        })

    for pipeline in pipelines:
        tgt = target_map.get(pipeline.get("target_id"))
        try:
            result_data = json.loads(pipeline.get("result", "{}"))
        except (json.JSONDecodeError, TypeError):
            result_data = {}

        events.append({
            "event": "sec_dashboard_pipeline",
            "timestamp": pipeline.get("started_at"),
            "pipeline_id": pipeline.get("id"),
            "mode": pipeline.get("mode"),
            "status": pipeline.get("status"),
            "target_name": tgt.get("name", "") if tgt else "",
            "target_host": tgt.get("host", "") if tgt else "",
            "elapsed_seconds": result_data.get("elapsed_seconds"),
            "total_tools": result_data.get("total_tools"),
        })

    return json.dumps({
        "source": "sec-dashboard",
        "version": "1.0.0",
        "exported_at": datetime.utcnow().isoformat(),
        "total_events": len(events),
        "events": events,
    }, indent=2, ensure_ascii=False, default=str)


def _sanitize(text: str) -> str:
    """Strip non-latin-1 chars for fpdf Helvetica compatibility."""
    if not isinstance(text, str):
        text = str(text)
    replacements = {
        '\u2014': '--', '\u2013': '-', '\u2018': "'", '\u2019': "'",
        '\u201c': '"', '\u201d': '"', '\u2026': '...', '\u00a0': ' ',
        '\u2022': '-', '\u2192': '->', '\u2190': '<-', '\u221e': 'inf',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.encode('latin-1', errors='replace').decode('latin-1')


def _sanitize_dict(obj):
    """Recursively sanitize all strings in a dict/list structure."""
    if isinstance(obj, str):
        return _sanitize(obj)
    elif isinstance(obj, dict):
        return {k: _sanitize_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_dict(item) for item in obj]
    return obj


def _render_scan_results(pdf, tool: str, result: dict):
    """Render tool-specific findings into the PDF."""
    # Sanitize all string values in result
    result = _sanitize_dict(result)
    if tool == "port_scanner":
        pdf.kv_row("Host", result.get("host", ""))
        pdf.kv_row("Open Ports", f"{result.get('open_count', 0)}/{result.get('scanned_ports', 0)}")
        pdf.kv_row("Elapsed", f"{result.get('elapsed_seconds', '')}s")
        if result.get("open_ports"):
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(15, 5, "Port", border=1)
            pdf.cell(20, 5, "State", border=1)
            pdf.cell(45, 5, "Service", border=1, new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            for p in result["open_ports"]:
                pdf.cell(15, 5, str(p.get("port", "")), border=1)
                pdf.cell(20, 5, p.get("state", ""), border=1)
                pdf.cell(45, 5, p.get("service", ""), border=1, new_x="LMARGIN", new_y="NEXT")

    elif tool == "dns_recon":
        pdf.kv_row("Records", str(result.get("record_count", "")))
        records = result.get("records", {})
        for rtype, entries in records.items():
            if entries:
                vals = ", ".join(str(e.get("value", e)) if isinstance(e, dict) else str(e) for e in entries[:5])
                pdf.kv_row(f"  {rtype}", vals)

    elif tool == "subdomain_enum":
        pdf.kv_row("Found", str(result.get("count", "")))
        pdf.kv_row("Wordlist", str(result.get("wordlist_size", "")))
        pdf.kv_row("Elapsed", f"{result.get('elapsed_seconds', '')}s")
        if result.get("subdomains_found"):
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(60, 5, "Subdomain", border=1)
            pdf.cell(40, 5, "IP", border=1, new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            for sub in result["subdomains_found"]:
                pdf.cell(60, 5, sub.get("subdomain", ""), border=1)
                pdf.cell(40, 5, sub.get("ip", ""), border=1, new_x="LMARGIN", new_y="NEXT")

    elif tool == "http_probe":
        pdf.kv_row("URL", result.get("url", ""))
        pdf.kv_row("Status", str(result.get("status_code", "")))
        pdf.kv_row("Server", result.get("server", ""))
        pdf.kv_row("Content-Type", result.get("content_type", ""))
        pdf.kv_row("Size", f"{result.get('content_length', 0)} bytes")
        pdf.kv_row("Redirect", result.get("redirect_url", "None"))

    elif tool == "whois_lookup":
        pdf.kv_row("Domain", result.get("domain", ""))
        pdf.kv_row("Registrar", result.get("registrar", ""))
        pdf.kv_row("Created", result.get("creation_date", ""))
        pdf.kv_row("Expires", result.get("expiration_date", ""))
        pdf.kv_row("Name Servers", ", ".join(result.get("name_servers", [])[:3]))
        pdf.kv_row("Country", result.get("country", ""))

    elif tool == "ssl_analyzer":
        pdf.kv_row("TLS Version", result.get("tls_version", ""))
        pdf.kv_row("Cipher", result.get("cipher_suite", ""))
        pdf.kv_row("Bits", str(result.get("cipher_bits", "")))
        pdf.kv_row("Valid", str(result.get("valid", "")))
        pdf.kv_row("Not After", result.get("not_after", ""))
        pdf.kv_row("Issuer", str(result.get("issuer", {})))
        if result.get("subject"):
            pdf.kv_row("Subject", str(result["subject"]))

    elif tool == "header_analyzer":
        pdf.kv_row("Grade", result.get("grade", ""))
        pdf.kv_row("Score", f"{result.get('score', '')}/10")
        pdf.kv_row("URL", result.get("url", ""))
        if result.get("security_headers_present"):
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(0, 5, "Present:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            for h in result["security_headers_present"]:
                pdf.cell(0, 5, f"  + {h.get('header', '')}: {h.get('value', '')[:60]}", new_x="LMARGIN", new_y="NEXT")
        if result.get("security_headers_missing"):
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(200, 0, 0)
            pdf.cell(0, 5, "Missing:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 8)
            for h in result["security_headers_missing"]:
                pdf.cell(0, 5, f"  - {h.get('header', '')}: {h.get('description', '')[:60]}", new_x="LMARGIN", new_y="NEXT")

    elif tool == "tech_detector":
        pdf.kv_row("URL", result.get("url", ""))
        pdf.kv_row("Status", str(result.get("status", "")))
        pdf.kv_row("Server", result.get("server", ""))
        pdf.kv_row("Total Detected", str(result.get("total_detected", "")))
        for cat, techs in result.get("technologies", {}).items():
            pdf.kv_row(f"  {cat}", ", ".join(techs))

    elif tool == "dir_fuzzer":
        pdf.kv_row("Found", str(result.get("count", "")))
        if result.get("found_paths"):
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(60, 5, "Path", border=1)
            pdf.cell(15, 5, "Status", border=1)
            pdf.cell(20, 5, "Size", border=1, new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            for p in result["found_paths"][:20]:
                pdf.cell(60, 5, p.get("path", "")[:40], border=1)
                pdf.cell(15, 5, str(p.get("status", "")), border=1)
                pdf.cell(20, 5, str(p.get("size", "")), border=1, new_x="LMARGIN", new_y="NEXT")

    elif tool == "password_audit":
        pdf.kv_row("Strength", result.get("strength", ""))
        pdf.kv_row("Score", str(result.get("score", "")))
        analysis = result.get("analysis", {})
        pdf.kv_row("Length", str(analysis.get("length", "")))
        pdf.kv_row("Entropy", str(analysis.get("entropy", "")))
        pdf.kv_row("Breached", str(result.get("breached", "")))

    elif tool == "cve_search":
        pdf.kv_row("CVEs Found", str(result.get("count", "")))
        for cve in result.get("cves", [])[:10]:
            pdf.kv_row(f"  {cve.get('id', '')}", cve.get("summary", "")[:80])

    elif tool == "ping_sweep":
        alive = result.get("alive_hosts", [])
        pdf.kv_row("Alive Hosts", str(len(alive)))
        for h in alive[:10]:
            pdf.kv_row(f"  {h.get('ip', '')}", f"{h.get('rtt_ms', '')}ms")

    elif tool == "traceroute":
        hops = result.get("hops", [])
        pdf.kv_row("Hops", str(len(hops)))
        for h in hops[:15]:
            pdf.kv_row(f"  {h.get('hop', '')}", f"{h.get('host', h.get('ip', ''))}  {h.get('rtt_ms', '')}ms")

    elif tool == "asn_lookup":
        pdf.kv_row("ASN", result.get("asn", ""))
        pdf.kv_row("Name", result.get("name", ""))
        pdf.kv_row("Country", result.get("country", ""))
        pdf.kv_row("CIDR", result.get("cidr", ""))

    elif tool == "reverse_dns":
        pdf.kv_row("IP", result.get("ip", ""))
        pdf.kv_row("Hostname", result.get("hostname", ""))

    elif tool == "ct_logs":
        pdf.kv_row("Certificates", str(result.get("cert_count", "")))
        pdf.kv_row("Subdomains", str(result.get("unique_subdomains", "")))
        for sub in result.get("subdomains", [])[:10]:
            pdf.cell(0, 5, f"  {sub}", new_x="LMARGIN", new_y="NEXT")

    elif tool == "ip_geolocation":
        pdf.kv_row("IP", result.get("ip", ""))
        pdf.kv_row("Country", f"{result.get('country', '')} ({result.get('country_code', '')})")
        pdf.kv_row("City", result.get("city", ""))
        pdf.kv_row("ISP", result.get("isp", ""))
        pdf.kv_row("Org", result.get("org", ""))
        pdf.kv_row("Coordinates", f"{result.get('lat', '')}, {result.get('lon', '')}")

    elif tool == "shodan_lookup":
        pdf.kv_row("IP", result.get("ip", ""))
        pdf.kv_row("Ports", ", ".join(str(p) for p in result.get("ports", [])[:10]))
        pdf.kv_row("OS", result.get("os", ""))
        pdf.kv_row("Org", result.get("org", ""))

    elif tool == "cors_checker":
        pdf.kv_row("Vulnerable", str(result.get("vulnerable", False)))
        for finding in result.get("findings", [])[:5]:
            pdf.kv_row(f"  {finding.get('name', '')}", finding.get("description", "")[:60])

    elif tool == "csp_analyzer":
        pdf.kv_row("Grade", result.get("grade", ""))
        pdf.kv_row("Score", str(result.get("score", "")))
        for issue in result.get("issues", [])[:5]:
            pdf.kv_row(f"  {issue.get('severity', '')}", issue.get("description", "")[:60])

    elif tool == "sqli_scanner":
        pdf.kv_row("Vulnerable", str(result.get("vulnerable_count", 0)))
        for finding in result.get("findings", [])[:5]:
            pdf.kv_row(f"  {finding.get('param', '')}", finding.get("type", ""))

    elif tool == "xss_scanner":
        pdf.kv_row("Vulnerable", str(result.get("vulnerable_count", 0)))
        for finding in result.get("findings", [])[:5]:
            pdf.kv_row(f"  {finding.get('param', '')}", finding.get("type", ""))

    elif tool == "open_redirect":
        pdf.kv_row("Vulnerable", str(result.get("vulnerable", False)))
        for finding in result.get("findings", [])[:5]:
            pdf.kv_row(f"  {finding.get('param', '')}", finding.get("url", "")[:60])

    else:
        # Generic fallback
        pdf.add_json_block(result, max_lines=30)


def generate_all_pdf(scans: list, pipelines: list, targets: list) -> bytes:
    """Generate PDF report for all scans and pipelines with full results."""
    pdf = ReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    target_map = {t["id"]: t for t in targets}

    # Summary
    pdf.section_title("Full Export Summary")
    pdf.kv_row("Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    pdf.kv_row("Total Scans", str(len(scans)))
    pdf.kv_row("Total Pipelines", str(len(pipelines)))
    pdf.kv_row("Total Targets", str(len(targets)))
    completed = sum(1 for s in scans if s.get("status") == "completed")
    failed = sum(1 for s in scans if s.get("status") == "failed")
    pdf.kv_row("Scans Completed", str(completed))
    pdf.kv_row("Scans Failed", str(failed))
    pdf.ln(4)

    # Targets
    if targets:
        pdf.section_title("Targets")
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(15, 6, "ID", border=1)
        pdf.cell(50, 6, "Name", border=1)
        pdf.cell(60, 6, "Host", border=1)
        pdf.cell(40, 6, "Scans", border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for t in targets:
            scan_count = sum(1 for s in scans if s.get("target_id") == t["id"])
            pdf.cell(15, 6, str(t.get("id", "")), border=1)
            pdf.cell(50, 6, str(t.get("name", ""))[:30], border=1)
            pdf.cell(60, 6, str(t.get("host", ""))[:40], border=1)
            pdf.cell(40, 6, str(scan_count), border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    # Scans overview table
    if scans:
        pdf.section_title("Scans Overview")
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(12, 6, "ID", border=1)
        pdf.cell(35, 6, "Tool", border=1)
        pdf.cell(40, 6, "Target", border=1)
        pdf.cell(18, 6, "Status", border=1)
        pdf.cell(14, 6, "OK", border=1)
        pdf.cell(35, 6, "Started", border=1)
        pdf.cell(35, 6, "Elapsed", border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        for s in scans:
            tgt = target_map.get(s.get("target_id"))
            tgt_host = tgt.get("host", "")[:25] if tgt else ""
            result_data = {}
            if s.get("result"):
                try:
                    result_data = json.loads(s["result"])
                except (json.JSONDecodeError, TypeError):
                    result_data = {}
            success_str = "Yes" if result_data.get("success") else "No"
            elapsed = f"{result_data.get('elapsed_seconds', '')}s" if result_data.get("elapsed_seconds") else ""
            started = str(s.get("started_at", ""))[:19]
            pdf.cell(12, 5, str(s.get("id", "")), border=1)
            pdf.cell(35, 5, str(s.get("tool", ""))[:22], border=1)
            pdf.cell(40, 5, tgt_host, border=1)
            pdf.cell(18, 5, str(s.get("status", ""))[:8], border=1)
            pdf.cell(14, 5, success_str, border=1)
            pdf.cell(35, 5, started, border=1)
            pdf.cell(35, 5, elapsed, border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # Detailed results per scan
        pdf.section_title("Scan Results")
        for s in scans:
            if s.get("status") != "completed":
                continue
            result_data = {}
            if s.get("result"):
                try:
                    result_data = json.loads(s["result"])
                except (json.JSONDecodeError, TypeError):
                    result_data = {}
            if not result_data.get("success"):
                continue

            tgt = target_map.get(s.get("target_id"))
            tgt_host = tgt.get("host", "") if tgt else ""
            tool = s.get("tool", "unknown")

            # Check page space — add page if near bottom
            if pdf.get_y() > 240:
                pdf.add_page()

            pdf.set_font("Helvetica", "B", 10)
            pdf.set_fill_color(40, 40, 40)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(0, 7, f"  #{s.get('id', '')}  {tool}  ->  {tgt_host}", fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)

            result = result_data.get("result", result_data)
            _render_scan_results(pdf, tool, result)
            pdf.ln(4)

    # Pipelines
    if pipelines:
        pdf.add_page()
        pdf.section_title("Pipelines")
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(12, 6, "ID", border=1)
        pdf.cell(30, 6, "Mode", border=1)
        pdf.cell(40, 6, "Target", border=1)
        pdf.cell(18, 6, "Status", border=1)
        pdf.cell(35, 6, "Started", border=1)
        pdf.cell(25, 6, "Tools", border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        for p in pipelines:
            tgt = target_map.get(p.get("target_id"))
            tgt_host = tgt.get("host", "")[:25] if tgt else ""
            result_data = {}
            if p.get("result"):
                try:
                    result_data = json.loads(p["result"])
                except (json.JSONDecodeError, TypeError):
                    result_data = {}
            started = str(p.get("started_at", ""))[:19]
            total = str(result_data.get("total_tools", "")) if result_data else ""
            pdf.cell(12, 5, str(p.get("id", "")), border=1)
            pdf.cell(30, 5, str(p.get("mode", ""))[:18], border=1)
            pdf.cell(40, 5, tgt_host, border=1)
            pdf.cell(18, 5, str(p.get("status", ""))[:8], border=1)
            pdf.cell(35, 5, started, border=1)
            pdf.cell(25, 5, total, border=1, new_x="LMARGIN", new_y="NEXT")

    return bytes(pdf.output())


def generate_scan_pdf(scan: dict, target: dict = None) -> bytes:
    """Generate PDF report for a single scan."""
    pdf = ReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    # Title
    tool = scan.get("tool", "Unknown")
    host = target.get("host", "") if target else ""
    pdf.section_title(f"Scan: {tool} -> {host}")

    # Metadata
    pdf.kv_row("Scan ID", str(scan.get("id", "")))
    pdf.kv_row("Tool", tool)
    pdf.kv_row("Target", f"{target.get('name', '')} ({host})" if target else str(scan.get("target_id", "")))
    pdf.kv_row("Status", scan.get("status", ""))
    pdf.kv_row("Started", str(scan.get("started_at", "")))
    pdf.kv_row("Finished", str(scan.get("finished_at", "")))
    pdf.ln(4)

    # Result
    result_data = {}
    if scan.get("result"):
        try:
            result_data = json.loads(scan["result"])
        except (json.JSONDecodeError, TypeError):
            result_data = {"raw": scan["result"]}

    if result_data.get("success"):
        pdf.section_title("Result Summary")
        result = result_data.get("result", {})

        # Tool-specific formatting
        if tool == "port_scanner":
            pdf.kv_row("Host", result.get("host", ""))
            pdf.kv_row("Ports Scanned", str(result.get("scanned_ports", "")))
            pdf.kv_row("Open Ports", str(result.get("open_count", "")))
            pdf.kv_row("Elapsed", f"{result.get('elapsed_seconds', '')}s")
            pdf.ln(2)
            if result.get("open_ports"):
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(20, 6, "Port", border=1)
                pdf.cell(30, 6, "State", border=1)
                pdf.cell(50, 6, "Service", border=1, new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                for p in result["open_ports"]:
                    pdf.cell(20, 6, str(p.get("port", "")), border=1)
                    pdf.cell(30, 6, p.get("state", ""), border=1)
                    pdf.cell(50, 6, p.get("service", ""), border=1, new_x="LMARGIN", new_y="NEXT")

        elif tool == "header_analyzer":
            pdf.kv_row("Grade", result.get("grade", ""))
            pdf.kv_row("Score", result.get("score", ""))
            pdf.kv_row("URL", result.get("url", ""))
            pdf.ln(2)
            if result.get("security_headers_missing"):
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 6, "Missing Headers:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                for h in result["security_headers_missing"]:
                    pdf.cell(0, 6, f"  - {h.get('header', '')}: {h.get('description', '')}", new_x="LMARGIN", new_y="NEXT")

        elif tool == "ssl_analyzer":
            pdf.kv_row("TLS Version", result.get("tls_version", ""))
            pdf.kv_row("Cipher", result.get("cipher_suite", ""))
            pdf.kv_row("Bits", str(result.get("cipher_bits", "")))
            pdf.kv_row("Valid", str(result.get("valid", "")))
            pdf.kv_row("Not After", result.get("not_after", ""))
            pdf.kv_row("Issuer", str(result.get("issuer", {})))

        elif tool == "password_audit":
            pdf.kv_row("Strength", result.get("strength", ""))
            pdf.kv_row("Score", result.get("score", ""))
            analysis = result.get("analysis", {})
            pdf.kv_row("Length", str(analysis.get("length", "")))
            pdf.kv_row("Entropy", str(analysis.get("entropy", "")))
            pdf.kv_row("Breached", str(result.get("breached", "")))

        else:
            # Generic: dump result as JSON
            pdf.add_json_block(result)

        pdf.ln(4)

    elif result_data.get("error"):
        pdf.section_title("Error")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 6, str(result_data.get("error", "")))

    # Raw JSON appendix
    pdf.add_page()
    pdf.section_title("Raw JSON Output")
    pdf.add_json_block(result_data, max_lines=80)

    return bytes(pdf.output())


def generate_pipeline_pdf(pipeline: dict, target: dict = None) -> bytes:
    """Generate PDF report for a pipeline run."""
    pdf = ReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    mode = pipeline.get("mode", "Unknown")
    host = target.get("host", "") if target else ""
    pdf.section_title(f"Pipeline: {mode} -> {host}")

    # Metadata
    pdf.kv_row("Pipeline ID", str(pipeline.get("id", "")))
    pdf.kv_row("Mode", mode)
    pdf.kv_row("Target", f"{target.get('name', '')} ({host})" if target else str(pipeline.get("target_id", "")))
    pdf.kv_row("Status", pipeline.get("status", ""))
    pdf.kv_row("Started", str(pipeline.get("started_at", "")))
    pdf.kv_row("Finished", str(pipeline.get("finished_at", "")))
    pdf.ln(4)

    # Parse result
    result_data = {}
    if pipeline.get("result"):
        try:
            result_data = json.loads(pipeline["result"])
        except (json.JSONDecodeError, TypeError):
            result_data = {}

    if result_data:
        pdf.kv_row("Total Tools", str(result_data.get("total_tools", "")))
        pdf.kv_row("Elapsed", f"{result_data.get('elapsed_seconds', '')}s")
        pdf.ln(4)

        # Phases
        phases = result_data.get("phases", {})
        for phase_name, tools in phases.items():
            pdf.section_title(f"Phase: {phase_name}")
            for tool_name, tool_result in tools.items():
                success = tool_result.get("success", False)
                elapsed = tool_result.get("elapsed_seconds", 0)
                status_mark = "[OK]" if success else "[FAIL]"
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 6, f"{status_mark} {tool_name} ({elapsed}s)", new_x="LMARGIN", new_y="NEXT")

                if tool_result.get("success") and tool_result.get("result"):
                    tr = tool_result["result"]
                    # Compact summary per tool
                    if tool_name == "port_scanner":
                        pdf.kv_row("  Open Ports", f"{tr.get('open_count', 0)}/{tr.get('scanned_ports', 0)}")
                    elif tool_name == "header_analyzer":
                        pdf.kv_row("  Grade", tr.get("grade", ""))
                    elif tool_name == "ssl_analyzer":
                        pdf.kv_row("  TLS", tr.get("tls_version", ""))
                        pdf.kv_row("  Valid", str(tr.get("valid", "")))
                    elif tool_name == "dns_recon":
                        pdf.kv_row("  Records", str(tr.get("record_count", "")))
                    elif tool_name == "subdomain_enum":
                        pdf.kv_row("  Found", str(tr.get("count", "")))
                    elif tool_name == "dir_fuzzer":
                        pdf.kv_row("  Paths Found", str(tr.get("count", "")))
                    elif tool_name == "cve_search":
                        pdf.kv_row("  CVEs", str(tr.get("count", "")))
                    elif tool_name == "system_info":
                        os_info = tr.get("os", {})
                        pdf.kv_row("  OS", f"{os_info.get('system', '')} {os_info.get('release', '')}")
                elif tool_result.get("error"):
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(200, 0, 0)
                    pdf.cell(0, 5, f"  Error: {str(tool_result.get('error', ''))[:100]}", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_text_color(0, 0, 0)
                pdf.ln(1)

    # Raw JSON appendix
    pdf.add_page()
    pdf.section_title("Raw JSON Output")
    pdf.add_json_block(result_data, max_lines=100)

    return bytes(pdf.output())
