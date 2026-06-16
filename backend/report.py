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
