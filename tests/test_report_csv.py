"""CSV exports (SIEM / spreadsheets): report helpers + export endpoints.

No network. Pure helpers are tested directly; the HTTP endpoints run against a
throwaway SQLite DB in tmp_path by monkeypatching models.DB_PATH (Fase 0.4
pattern), so the real data/sec.db is never touched.
"""
import asyncio
import csv
import io
import json

import pytest
from fastapi import HTTPException

from backend import models, report


def _run(coro):
    return asyncio.run(coro)


def _scan(findings=None, result=None):
    return {
        "id": 7, "tool": "header_analyzer", "status": "completed",
        "target_id": 1, "started_at": "2026-08-27T10:00:00",
        "finished_at": "2026-08-27T10:00:05",
        "result": result if result is not None else json.dumps({
            "success": True, "elapsed_seconds": 4.2}),
        "findings": findings, "score": 42,
    }


def _target():
    return {"id": 1, "name": "t", "host": "example.com"}


def _rows(text):
    """Decode the BOM-prefixed CSV back into rows (round-trip check)."""
    assert text.startswith("\ufeff")
    return list(csv.reader(io.StringIO(text.lstrip("\ufeff"))))


FINDINGS = [
    {"finding_id": "a" * 12, "severity": "high", "category": "headers",
     "title": "HSTS missing", "description": "No HSTS header",
     "evidence": 'set-cookie: a=1, b=2\nline two', "cve": "", "confidence": 0.9,
     "remediation": "Add Strict-Transport-Security"},
    {"finding_id": "b" * 12, "severity": "low", "category": "headers",
     "title": "Server banner", "description": "", "evidence": "Server: nginx",
     "cve": "", "confidence": 0.5, "remediation": ""},
]


def test_scan_csv_header_bom_and_crlf():
    text = report.generate_scan_csv(_scan(findings=json.dumps(FINDINGS)), _target())
    assert "\r\n" in text and not text.startswith("\n")
    rows = _rows(text)
    assert rows[0] == report.SCAN_CSV_FIELDS


def test_scan_csv_one_row_per_finding_with_metadata():
    text = report.generate_scan_csv(_scan(findings=json.dumps(FINDINGS)), _target())
    rows = _rows(text)
    assert len(rows) == 1 + len(FINDINGS)
    r0, r1 = rows[1], rows[2]
    # Run metadata repeated on every row (self-contained for SIEM)
    assert r0[:9] == r1[:9]
    assert r0[0] == "7" and r0[1] == "header_analyzer"
    assert r0[3] == "t" and r0[4] == "example.com"
    assert r0[8] == "42"  # score
    # Finding fields mapped in order
    assert r0[9:18] == ["a" * 12, "high", "headers", "HSTS missing",
                       "No HSTS header", 'set-cookie: a=1, b=2\nline two', "", "0.9",
                       "Add Strict-Transport-Security"]
    assert r1[9] == "b" * 12 and r1[10] == "low"


def test_scan_csv_no_findings_keeps_single_summary_row():
    text = report.generate_scan_csv(_scan(findings="[]"), _target())
    rows = _rows(text)
    assert len(rows) == 2  # header + one summary row, event preserved
    assert rows[1][0] == "7" and rows[1][9:] == [""] * 9


def test_scan_csv_null_and_corrupt_findings_tolerated():
    for blob in (None, "{not json", '"a string"'):
        text = report.generate_scan_csv(_scan(findings=blob), _target())
        rows = _rows(text)
        assert len(rows) == 2


def test_scan_csv_quoting_round_trips_commas_and_newlines():
    text = report.generate_scan_csv(_scan(findings=json.dumps(FINDINGS)), _target())
    rows = _rows(text)
    assert rows[1][14] == 'set-cookie: a=1, b=2\nline two'


def test_pipeline_csv_mode_tools_and_per_finding_tool():
    pipeline = {
        "id": 3, "mode": "full_depth", "status": "completed", "target_id": 1,
        "started_at": "2026-08-27T11:00:00", "finished_at": None,
        "result": json.dumps({"elapsed_seconds": 30.0, "total_tools": 5}),
        "findings": json.dumps(FINDINGS), "score": 55,
    }
    text = report.generate_pipeline_csv(pipeline, _target())
    rows = _rows(text)
    assert rows[0] == report.PIPELINE_CSV_FIELDS
    assert len(rows) == 1 + len(FINDINGS)
    r0 = rows[1]
    # run cols: id, mode, status, name, host, started, finished, elapsed, tools, score
    assert r0[:10] == ["3", "full_depth", "completed", "t", "example.com",
                       "2026-08-27T11:00:00", "", "30.0", "5", "55"]
    # tool column comes from the finding itself (per-tool identity)
    assert r0[10] == ""  # findings without explicit tool stay empty
    assert r0[11] == "a" * 12 and r0[12] == "high"


def test_pipeline_csv_no_findings_summary_row():
    pipeline = {"id": 3, "mode": "fast", "status": "completed", "target_id": 1,
               "started_at": None, "finished_at": None,
               "result": json.dumps({}), "findings": None, "score": 0}
    rows = _rows(report.generate_pipeline_csv(pipeline, _target()))
    assert len(rows) == 2
    assert rows[1][10:] == [""] * 10


# -- Endpoints (temp DB, no network) -------------------------------------

async def _seed_scan(findings):
    db = await models.get_db()
    await db.execute("INSERT INTO targets (name, host) VALUES ('t', 'example.com')")
    await db.execute(
        "INSERT INTO scans (target_id, tool, status, result, findings, score, started_at) "
        "VALUES (1, 'header_analyzer', 'completed', ?, ?, 42, '2026-08-27T10:00:00')",
        (json.dumps({"success": True}), findings))
    await db.commit()
    await db.close()


def test_export_scan_csv_endpoint(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "csv.db")
    _run(models.init_db())
    _run(_seed_scan(json.dumps(FINDINGS)))

    resp = _run(main.export_scan_csv(1))
    assert resp.media_type == "text/csv; charset=utf-8"
    body = resp.body.decode("utf-8")
    rows = list(csv.reader(io.StringIO(body.lstrip("\ufeff"))))
    assert rows[0] == report.SCAN_CSV_FIELDS
    assert len(rows) == 1 + len(FINDINGS)
    assert "example.com" in body and "HSTS missing" in body
    assert 'filename="scan_1.csv"' in resp.headers["content-disposition"]


def test_export_scan_csv_endpoint_404(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "csv404.db")
    _run(models.init_db())
    with pytest.raises(HTTPException) as exc:
        _run(main.export_scan_csv(99))
    assert exc.value.status_code == 404


def test_export_pipeline_csv_endpoint_rows(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "cpip2.db")
    _run(models.init_db())

    async def seed():
        db = await models.get_db()
        await db.execute("INSERT INTO targets (name, host) VALUES ('t', 'example.com')")
        await db.execute(
            "INSERT INTO pipelines (target_id, mode, status, result, findings, score, started_at) "
            "VALUES (1, 'full_depth', 'completed', ?, ?, 55, '2026-08-27T11:00:00')",
            (json.dumps({"total_tools": 5}), json.dumps(FINDINGS)))
        await db.commit()
        await db.close()

    _run(seed())
    resp = _run(main.export_pipeline_csv(1))
    assert resp.media_type == "text/csv; charset=utf-8"
    body = resp.body.decode("utf-8")
    rows = list(csv.reader(io.StringIO(body.lstrip("\ufeff"))))
    assert rows[0] == report.PIPELINE_CSV_FIELDS
    assert len(rows) == 1 + len(FINDINGS)
    assert rows[1][1] == "full_depth" and rows[1][8] == "5"
    assert 'filename="pipeline_1.csv"' in resp.headers["content-disposition"]
