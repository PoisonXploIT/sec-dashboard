"""Fase J3: Jev AI verdicts in exports (JSON/Splunk, CSV, executive PDF).

No network. Pure helpers over synthetic scan/pipeline rows. Rule under test:
without result.jev every export stays byte-identical to the pre-J3 output;
with result.jev.status == "ok" the exports gain AI verdict fields.
"""
import csv
import io
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


FINDINGS = [
    {"finding_id": "a" * 12, "severity": "high", "category": "headers",
     "title": "HSTS missing", "description": "No HSTS header",
     "evidence": "", "cve": "", "confidence": 0.9, "remediation": ""},
    {"finding_id": "b" * 12, "severity": "low", "category": "headers",
     "title": "Server banner", "description": "",
     "evidence": "", "cve": "", "confidence": 0.5, "remediation": ""},
]

JEV = {
    "status": "ok",
    "requested_model": "jev-1.13.0",
    "model": "jev-1.13.0",
    "count": 2,
    "truncated": False,
    "usage": {"input_tokens": 4288, "output_tokens": 0},
    "verdicts": {
        "a" * 12: {"verdict": "true_positive", "verdict_confidence": 0.97,
                   "severity_score": 2.5, "immediate_action": 0.4},
        "b" * 12: {"verdict": "noise", "verdict_confidence": 0.8,
                  "severity_score": 0.5, "immediate_action": 0.1},
    },
}


def _scan(jev=None, llm_explanations=None):
    result = {"success": True, "elapsed_seconds": 4.2, "result": {"grade": "C"}}
    if jev is not None:
        result["jev"] = jev
    if llm_explanations is not None:
        result["llm_explanations"] = llm_explanations
    return {
        "id": 7, "tool": "header_analyzer", "status": "completed",
        "target_id": 1, "started_at": "2026-08-27T10:00:00",
        "finished_at": "2026-08-27T10:00:05",
        "result": json.dumps(result),
        "findings": json.dumps(FINDINGS), "score": 42,
    }


def _pipeline(jev=None, llm_explanations=None):
    result = {"total_tools": 2, "elapsed_seconds": 60.0, "score": 42,
              "phases": {}, "findings": FINDINGS}
    if jev is not None:
        result["jev"] = jev
    if llm_explanations is not None:
        result["llm_explanations"] = llm_explanations
    return {
        "id": 9, "mode": "fast", "status": "completed", "target_id": 1,
        "started_at": "2026-08-27T10:00:00", "finished_at": "2026-08-27T10:01:00",
        "result": json.dumps(result),
        "findings": json.dumps(FINDINGS), "score": 42,
    }


def _target():
    return {"id": 1, "name": "t", "host": "example.com"}


def _rows(text):
    assert text.startswith("\ufeff")
    return list(csv.reader(io.StringIO(text.lstrip("\ufeff"))))


# ── JSON exports (Splunk-compatible) ────────────────────────────

def test_scan_json_ai_block_when_jev_ok():
    export = json.loads(report.generate_scan_json(_scan(JEV), _target()))
    assert "ai" in export
    assert export["ai"]["model"] == "jev-1.13.0"
    by_id = {v["finding_id"]: v for v in export["ai"]["verdicts"]}
    assert by_id["a" * 12] == {
        "finding_id": "a" * 12, "ai_verdict": "true_positive",
        "ai_confidence": 0.97, "ai_severity_score": 2.5,
        "ai_immediate_action": 0.4, "triage": "immediate",
    }
    assert by_id["b" * 12]["ai_verdict"] == "noise"
    assert by_id["b" * 12]["triage"] == "none"


def test_scan_json_ai_block_carries_triage_summary():
    export = json.loads(report.generate_scan_json(_scan(JEV), _target()))
    # a*12: tp conf .97 sev 2.5 -> immediate; b*12: noise conf .8 -> none.
    assert export["ai"]["triage_summary"] == {
        "immediate": 1, "scheduled": 0, "review": 0, "none": 1,
    }


def test_scan_json_low_confidence_verdict_triage_is_null():
    jev = dict(JEV)
    jev["verdicts"] = {"a" * 12: dict(JEV["verdicts"]["a" * 12], verdict_confidence=0.2)}
    export = json.loads(report.generate_scan_json(_scan(jev), _target()))
    by_id = {v["finding_id"]: v for v in export["ai"]["verdicts"]}
    assert by_id["a" * 12]["triage"] is None
    assert export["ai"]["triage_summary"] == {"immediate": 0, "scheduled": 0,
                                               "review": 0, "none": 0}


def test_scan_json_no_ai_key_without_jev():
    export = json.loads(report.generate_scan_json(_scan(), _target()))
    assert "ai" not in export
    # Pre-J3 field set, untouched.
    assert list(export.keys()) == ["event", "timestamp", "scan_id", "tool",
                                   "status", "target", "elapsed_seconds",
                                   "success", "result"]


def test_scan_json_skipped_jev_is_treated_as_absent():
    jev = dict(JEV, status="skipped", reason="disabled")
    export = json.loads(report.generate_scan_json(_scan(jev), _target()))
    assert "ai" not in export


def test_pipeline_json_ai_block_when_jev_ok():
    export = json.loads(report.generate_pipeline_json(_pipeline(JEV), _target()))
    assert export["ai"]["model"] == "jev-1.13.0"
    assert len(export["ai"]["verdicts"]) == 2


def test_all_json_events_carry_ai_block():
    text = report.generate_all_json([_scan(JEV)], [_pipeline(JEV)], [_target()])
    data = json.loads(text)
    events = {e["event"]: e for e in data["events"]}
    assert len(events["sec_dashboard_scan"]["ai"]["verdicts"]) == 2
    assert len(events["sec_dashboard_pipeline"]["ai"]["verdicts"]) == 2


def test_all_json_without_jev_has_no_ai_key():
    text = report.generate_all_json([_scan()], [_pipeline()], [_target()])
    data = json.loads(text)
    for e in data["events"]:
        assert "ai" not in e


# ── CSV exports (SIEM / spreadsheets) ───────────────────────────

def test_scan_csv_ai_columns_when_jev_ok():
    text = report.generate_scan_csv(_scan(JEV), _target())
    rows = _rows(text)
    assert rows[0] == list(report.SCAN_CSV_FIELDS) + list(report.AI_CSV_FIELDS) + [report.TRIAGE_CSV_FIELD]
    r0, r1 = rows[1], rows[2]
    # Values joined by finding_id, appended after the standard fields.
    assert r0[-5:] == ["true_positive", "0.97", "2.5", "0.4", "ACCION INMEDIATA"]
    assert r1[-5:] == ["noise", "0.8", "0.5", "0.1", "SIN ACCION"]


def test_scan_csv_low_confidence_verdict_has_empty_triage():
    jev = dict(JEV)
    jev["verdicts"] = {"a" * 12: dict(JEV["verdicts"]["a" * 12], verdict_confidence=0.2)}
    rows = _rows(report.generate_scan_csv(_scan(jev), _target()))
    assert rows[1][-5:] == ["true_positive", "0.2", "2.5", "0.4", ""]


def test_scan_csv_byte_identical_without_jev():
    text = report.generate_scan_csv(_scan(), _target())
    rows = _rows(text)
    assert rows[0] == list(report.SCAN_CSV_FIELDS)  # no AI columns at all


def test_pipeline_csv_ai_columns_after_mid_fields():
    text = report.generate_pipeline_csv(_pipeline(JEV), _target())
    rows = _rows(text)
    assert rows[0] == list(report.PIPELINE_CSV_FIELDS) + list(report.AI_CSV_FIELDS) + [report.TRIAGE_CSV_FIELD]
    assert rows[1][-5:] == ["true_positive", "0.97", "2.5", "0.4", "ACCION INMEDIATA"]


def test_csv_ai_join_falls_back_to_index_for_legacy_ids():
    # Legacy shape: findings without stable ids, so jev.py keyed verdicts by
    # index ("0"/"1") — the CSV join must fall back to the row index.
    jev = dict(JEV)
    jev["verdicts"] = {"0": JEV["verdicts"]["a" * 12], "1": JEV["verdicts"]["b" * 12]}
    findings = [dict(FINDINGS[0], finding_id=""), dict(FINDINGS[1], finding_id="")]
    scan = _scan(jev)
    scan["findings"] = json.dumps(findings)
    text = report.generate_scan_csv(scan, _target())
    rows = _rows(text)
    assert rows[1][-5:] == ["true_positive", "0.97", "2.5", "0.4", "ACCION INMEDIATA"]
    assert rows[2][-5:] == ["noise", "0.8", "0.5", "0.1", "SIN ACCION"]


# ── Executive PDF ───────────────────────────────────────────────

def _exec_text(pipeline: dict) -> str:
    # fpdf escapes parentheses in text ops; unescape for readable asserts.
    return _pdf_text(bytes(report.generate_executive_pdf(pipeline, _target()))) \
        .replace("\\(", "(").replace("\\)", ")")


def test_executive_pdf_ai_section_when_jev_ok():
    text = _exec_text(_pipeline(JEV))
    assert "AI Verdicts (Jev)" in text
    assert "jev-1.13.0" in text
    assert "true_positive" in text and "noise" in text
    # Composite risk ordering inside the AI section: high x 2.5 before
    # low x 0.5 (check positions after the section title, not the whole doc).
    ai_pos = text.index("AI Verdicts (Jev)")
    assert text.index("HSTS missing", ai_pos) < text.index("Server banner", ai_pos)


def test_scan_pdf_ai_section_when_jev_ok():
    text = _pdf_text(bytes(report.generate_scan_pdf(_scan(JEV), _target()))) \
        .replace("\\(", "(").replace("\\)", ")")
    assert "AI Verdicts (Jev)" in text
    assert "jev-1.13.0" in text and "true_positive" in text


def test_scan_pdf_triage_section_and_legend_when_jev_ok():
    text = _pdf_text(bytes(report.generate_scan_pdf(_scan(JEV), _target()))) \
        .replace("\\(", "(").replace("\\)", ")")
    assert "Triage: accion requerida" in text
    assert "ACCION INMEDIATA" in text and "SIN ACCION" in text
    # a*12 (high x 2.5, immediate) is listed before b*12 by composite risk.
    triage_pos = text.index("Triage: accion requerida")
    assert text.index("HSTS missing", triage_pos) < text.index("Server banner", triage_pos)
    # Static legend (J4b).
    assert "Como interpretar los datos AI" in text
    assert "true_positive (real issue)" in text


def test_scan_pdf_no_ai_section_without_jev():
    text = _pdf_text(bytes(report.generate_scan_pdf(_scan(), _target())))
    assert "AI Verdicts" not in text
    assert "Triage: accion requerida" not in text
    assert "Como interpretar los datos AI" not in text


def test_pipeline_pdf_ai_section_when_jev_ok():
    text = _pdf_text(bytes(report.generate_pipeline_pdf(_pipeline(JEV), _target()))) \
        .replace("\\(", "(").replace("\\)", ")")
    assert "AI Verdicts (Jev)" in text
    assert "jev-1.13.0" in text and "noise" in text


def test_pipeline_pdf_no_ai_section_without_jev():
    text = _pdf_text(bytes(report.generate_pipeline_pdf(_pipeline(), _target())))
    assert "AI Verdicts" not in text
    assert "Triage: accion requerida" not in text


def test_executive_pdf_no_ai_section_without_jev():
    assert "AI Verdicts" not in _exec_text(_pipeline())


def test_executive_pdf_skipped_jev_is_treated_as_absent():
    jev = dict(JEV, status="skipped", reason="no_api_key")
    assert "AI Verdicts" not in _exec_text(_pipeline(jev))


# ── J4c: read-only query inspector (GET /api/jev/query) ───────────────

def test_jev_query_inspector_is_read_only_and_bounded():
    import asyncio

    import backend.main as main

    res = asyncio.run(main.get_jev_query(n=99))  # bounded to 3
    assert "Nothing is sent" in res["note"]
    assert res["questions_template_repeated_per_finding"] == 3
    q0 = res["questions_for_finding_0"]
    assert set(q0.keys()) == {"f0_verdict", "f0_sev", "f0_action"}
    assert q0["f0_verdict"]["type"] == "choice"
    assert q0["f0_sev"]["type"] == "score"
    assert q0["f0_action"]["type"] == "noul"
    # Synthetic state: no real finding data can leak.
    assert res["sample_state"][0]["title"].startswith("SAMPLE_FINDING_TITLE")


# ── J5d: local LLM explanations in scan/pipeline PDFs (referencial) ───
# Generated at run completion and persisted in the result JSON; the PDF
# renders whatever the result carries.

LLM_EXPLS = [
    {"title": "HSTS missing", "model": "dirk-test-1b",
     "resumen": "El sitio no envia HSTS.",
     "porque": "Jev lo marca como true positive con confianza alta.",
     "sugerencia": "Anadir cabecera Strict-Transport-Security."},
    {"title": "Server banner", "status": "unavailable", "reason": "timeout"},
]


def test_scan_pdf_llm_explanations_section():
    text = _pdf_text(bytes(report.generate_scan_pdf(_scan(JEV, llm_explanations=LLM_EXPLS), _target()))) \
        .replace("\(", "(").replace("\)", ")")
    assert "Explicaciones LLM local" in text
    assert "El sitio no envia HSTS." in text
    assert "Anadir cabecera Strict-Transport-Security." in text
    assert "dirk-test-1b" in text
    # Unavailable items are shown with their reason, not as a failure.
    assert "no disponible (timeout)" in text


def test_pipeline_pdf_llm_explanations_section():
    text = _pdf_text(bytes(report.generate_pipeline_pdf(_pipeline(JEV, llm_explanations=LLM_EXPLS), _target()))) \
        .replace("\(", "(").replace("\)", ")")
    assert "Explicaciones LLM local" in text


def test_scan_pdf_without_llm_explanations_has_no_section():
    text = _pdf_text(bytes(report.generate_scan_pdf(_scan(JEV), _target()))) \
        .replace("\(", "(").replace("\)", ")")
    assert "Explicaciones LLM local" not in text
