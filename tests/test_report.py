"""Tests for report generation (JSON exports + PDF bytes). No network."""
import json
import re
import zlib

from backend import report


def _pdf_text(data: bytes) -> str:
    """Extract visible text from fpdf2 output by inflating its Flate streams."""
    chunks = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        try:
            dec = zlib.decompress(m.group(1))
        except zlib.error:
            continue
        chunks.extend(re.findall(rb"\(((?:[^()\\]|\\.)*)\)", dec))
    return " ".join(t.decode("latin-1") for t in chunks)


EXEC_PIPELINE = {
    "id": 9, "mode": "full_depth", "status": "completed", "target_id": 7,
    "started_at": "2026-08-27 09:00:00", "finished_at": "2026-08-27 09:04:00",
    "result": json.dumps({
        "total_tools": 5,
        "elapsed_seconds": 213.4,
        "score": 72,
        "findings": [
            {"tool": "subdomain_takeover", "category": "email",
             "severity": "critical", "title": "Dangling subdomain takeover",
             "confidence": 1.0, "description": "CNAME without A record",
             "evidence": "old.example.com -> s3.amazonaws.com"},
            {"tool": "dns_zone_hygiene", "category": "email",
             "severity": "high", "title": "Weak DKIM key strength",
             "confidence": 0.9, "description": "RSA below 2048 bits",
             "evidence": "select._domainkey 1024bits"},
            {"tool": "secret_leak_scan", "category": "web",
             "severity": "low", "title": "Weak token pattern in JS",
             "confidence": 0.5, "description": "Low-confidence match",
             "evidence": "/static/js/app.js"},
        ],
        "phases": {
            "Subdomains": {"subdomain_enum": {"success": True, "elapsed_seconds": 12.0,
                                                    "findings": []}},
            "Takeover": {"subdomain_takeover": {"success": True, "elapsed_seconds": 40.0,
                                                        "findings": [{}]}},
        },
    }),
}

EXEC_TARGET = {"id": 7, "name": "Example", "host": "example.com"}


SAMPLE_SCAN = {
    "id": 1,
    "tool": "port_scanner",
    "status": "completed",
    "target_id": 7,
    "started_at": "2026-08-17 12:00:00",
    "finished_at": "2026-08-17 12:00:05",
    "result": json.dumps({
        "success": True,
        "elapsed_seconds": 4.2,
        "result": {
            "host": "example.com",
            "scanned_ports": 100,
            "open_count": 2,
            "open_ports": [
                {"port": 80, "state": "open", "service": "http"},
                {"port": 443, "state": "open", "service": "https"},
            ],
        },
    }),
}

SAMPLE_TARGET = {"id": 7, "name": "Example", "host": "example.com"}


def test_generate_scan_json_roundtrip():
    out = json.loads(report.generate_scan_json(SAMPLE_SCAN, SAMPLE_TARGET))
    assert out["event"] == "sec_dashboard_scan"
    assert out["tool"] == "port_scanner"
    assert out["target"]["host"] == "example.com"
    assert out["success"] is True
    assert out["result"]["open_count"] == 2


def test_generate_scan_json_handles_bad_result_payload():
    bad = dict(SAMPLE_SCAN, result="this is not json {")
    out = json.loads(report.generate_scan_json(bad))
    assert out["result"] == {"raw": "this is not json {"}


def test_generate_all_json_counts_events():
    scans = [SAMPLE_SCAN]
    pipelines = []
    targets = [SAMPLE_TARGET]
    out = json.loads(report.generate_all_json(scans, pipelines, targets))
    assert out["total_events"] == 1
    assert out["events"][0]["target_host"] == "example.com"


def test_generate_scan_pdf_returns_pdf_bytes():
    data = report.generate_scan_pdf(SAMPLE_SCAN, SAMPLE_TARGET)
    assert isinstance(data, (bytes, bytearray))
    assert bytes(data).startswith(b"%PDF")


def test_generate_pipeline_pdf_returns_pdf_bytes():
    pipeline = {
        "id": 3, "mode": "fast", "status": "completed", "target_id": 7,
        "started_at": "2026-08-17 12:00:00", "finished_at": "2026-08-17 12:05:00",
        "result": json.dumps({
            "total_tools": 4, "elapsed_seconds": 120.0,
            "phases": {"Recon": {
                "whois_lookup": {"success": True, "elapsed_seconds": 3.1},
                "port_scanner": {"success": False, "error": "boom"},
            }},
        }),
    }
    data = report.generate_pipeline_pdf(pipeline, SAMPLE_TARGET)
    assert bytes(data).startswith(b"%PDF")


def test_executive_top_findings_ordering():
    findings, score = report.executive_findings_from_pipeline(EXEC_PIPELINE)
    assert score == 72
    assert len(findings) == 3
    top = report.executive_top_findings(findings)
    titles = [f["title"] for f in top]
    # critical (10 x 1.0) beats high (7 x 0.9) beats low (2 x 0.5)
    assert titles == [
        "Dangling subdomain takeover",
        "Weak DKIM key strength",
        "Weak token pattern in JS",
    ]


def test_executive_top_findings_limit():
    many = [{"severity": "info", "confidence": 1.0, "title": str(i)} for i in range(12)]
    assert len(report.executive_top_findings(many)) == 10


def test_executive_heatmap_counts():
    findings, _ = report.executive_findings_from_pipeline(EXEC_PIPELINE)
    matrix = report.executive_heatmap(findings)
    assert set(matrix) == {"email", "web"}
    assert matrix["email"]["critical"] == 1
    assert matrix["email"]["high"] == 1
    assert sum(matrix["email"].values()) == 2
    assert matrix["web"]["low"] == 1


def test_executive_pdf_contains_score_and_target():
    data = report.generate_executive_pdf(EXEC_PIPELINE, EXEC_TARGET)
    assert bytes(data).startswith(b"%PDF")
    text = _pdf_text(bytes(data))
    assert "72/100" in text
    assert "example.com" in text
    assert "Executive Report" in text


def test_executive_pdf_critical_before_low():
    data = report.generate_executive_pdf(EXEC_PIPELINE, EXEC_TARGET)
    text = _pdf_text(bytes(data))
    crit = text.find("Dangling subdomain takeover")
    low = text.find("Weak token pattern in JS")
    assert 0 <= crit < low


def test_executive_pdf_fallback_without_findings_or_score():
    pipeline = {"id": 1, "mode": "fast", "status": "completed", "target_id": 7,
                "result": json.dumps({"total_tools": 2, "phases": {}})}
    findings, score = report.executive_findings_from_pipeline(pipeline)
    assert findings == [] and score is None
    data = report.generate_executive_pdf(pipeline, EXEC_TARGET)
    assert bytes(data).startswith(b"%PDF")
    assert "n/a" in _pdf_text(bytes(data))


def test_generate_all_pdf_handles_unicode_and_unknown_tools():
    scan = dict(SAMPLE_SCAN, tool="mystery_tool")
    scan["result"] = json.dumps({
        "success": True,
        "elapsed_seconds": 1.0,
        "result": {"nota": "caf\u00e9 \u2014 \u2026 \u2192 unicode"},
    })
    data = report.generate_all_pdf([scan], [], [SAMPLE_TARGET])
    assert bytes(data).startswith(b"%PDF")
