"""Fase J5c: local LLM explanations auto-included in PDF exports.

No network: local_llm.explain_finding is monkeypatched. Rules under test:
- LLM disabled or Jev not ok -> None (PDF stays byte-identical to pre-J5c).
- Enabled + Jev ok -> top-N findings by composite risk, sequential calls,
  unavailable explanations kept as items, never raises.
"""
import asyncio
import json

import pytest

import backend.local_llm as local_llm
import backend.main as main


FINDINGS = [
    {"finding_id": "a" * 12, "severity": "high", "category": "headers",
     "title": "HSTS missing", "description": "No HSTS header",
     "tool": "header_analyzer"},
    {"finding_id": "b" * 12, "severity": "low", "category": "headers",
     "title": "Server banner", "description": "",
     "tool": "header_analyzer"},
]

JEV_OK = {
    "status": "ok", "model": "jev-1.13.0",
    "verdicts": {
        "a" * 12: {"verdict": "true_positive", "verdict_confidence": 0.97,
                   "severity_score": 2.5, "immediate_action": 0.4},
        "b" * 12: {"verdict": "noise", "verdict_confidence": 0.8,
                   "severity_score": 0.5, "immediate_action": 0.1},
    },
}


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _llm_enabled(monkeypatch):
    monkeypatch.setattr(local_llm, "get_local_llm_config",
                        lambda: {"enabled": True})


def test_disabled_returns_none(monkeypatch):
    monkeypatch.setattr(local_llm, "get_local_llm_config",
                        lambda: {"enabled": False})
    assert _run(main._pdf_llm_explanations({"jev": JEV_OK}, FINDINGS)) is None


def test_jev_not_ok_returns_none():
    assert _run(main._pdf_llm_explanations(
        {"jev": {"status": "skipped"}}, FINDINGS)) is None
    assert _run(main._pdf_llm_explanations({}, FINDINGS)) is None
    assert _run(main._pdf_llm_explanations(None, FINDINGS)) is None


def test_top_n_by_composite_risk(monkeypatch):
    calls = []

    async def fake_explain(state, verdict):
        calls.append(state["title"])
        return {"status": "ok", "model": "dirk-test", "explanation": {
            "resumen": f"R {state['title']}",
            "porque": f"P {state['title']}",
            "sugerencia": f"S {state['title']}"}}

    monkeypatch.setattr(local_llm, "explain_finding", fake_explain)
    out = _run(main._pdf_llm_explanations({"jev": JEV_OK}, FINDINGS))
    # high x 2.5 before low x 0.5 (same composite-risk rule as the UI).
    assert calls == ["HSTS missing", "Server banner"]
    assert out[0]["title"] == "HSTS missing"
    assert out[0]["resumen"] == "R HSTS missing"
    assert out[0]["model"] == "dirk-test"


def test_unavailable_explanation_kept_as_item(monkeypatch):
    async def fake_explain(state, verdict):
        return {"status": "unavailable", "reason": "timeout"}

    monkeypatch.setattr(local_llm, "explain_finding", fake_explain)
    out = _run(main._pdf_llm_explanations({"jev": JEV_OK}, FINDINGS))
    assert len(out) == 2
    assert all(i["status"] == "unavailable" and i["reason"] == "timeout"
               for i in out)


def test_top_n_capped(monkeypatch):
    many = [dict(FINDINGS[0], finding_id=f"f{i}", title=f"T{i}")
            for i in range(7)]
    jev = {"status": "ok", "verdicts": {f"f{i}": JEV_OK["verdicts"]["a" * 12]
                                        for i in range(7)}}
    calls = []

    async def fake_explain(state, verdict):
        calls.append(state["title"])
        return {"status": "ok", "model": "m", "explanation": {
            "resumen": "r", "porque": "p", "sugerencia": "s"}}

    monkeypatch.setattr(local_llm, "explain_finding", fake_explain)
    out = _run(main._pdf_llm_explanations({"jev": jev}, many))
    assert len(out) == main.LLM_PDF_TOP_N == 5
    assert len(calls) == 5


def test_export_findings_column_first_result_fallback():
    row = {"findings": json.dumps(FINDINGS)}
    assert main._export_findings(row, {}) == FINDINGS
    assert main._export_findings(
        {"findings": "not json"}, {"findings": FINDINGS}) == FINDINGS
    assert main._export_findings({}, {}) == []
