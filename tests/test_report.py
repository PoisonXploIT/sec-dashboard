"""Tests for report generation (JSON exports + PDF bytes). No network."""
import json

from backend import report


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


def test_generate_all_pdf_handles_unicode_and_unknown_tools():
    scan = dict(SAMPLE_SCAN, tool="mystery_tool")
    scan["result"] = json.dumps({
        "success": True,
        "elapsed_seconds": 1.0,
        "result": {"nota": "caf\u00e9 \u2014 \u2026 \u2192 unicode"},
    })
    data = report.generate_all_pdf([scan], [], [SAMPLE_TARGET])
    assert bytes(data).startswith(b"%PDF")
