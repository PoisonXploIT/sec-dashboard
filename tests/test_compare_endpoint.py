"""Phase 2: historical comparison endpoint (GET /api/pipelines/compare).

No network. Uses a throwaway SQLite DB in tmp_path by monkeypatching
models.DB_PATH (Fase 0.4 pattern), so the real data/sec.db is never touched.
"""
import asyncio
import json

import pytest
from fastapi import HTTPException

from backend import models


def _run(coro):
    return asyncio.run(coro)


async def _seed(pipelines: list[dict]) -> int:
    """Insert one target plus pipelines; returns the target id."""
    db = await models.get_db()
    await db.execute("INSERT INTO targets (name, host) VALUES ('t', 'example.com')")
    for p in pipelines:
        await db.execute(
            "INSERT INTO pipelines (target_id, mode, status, findings, score, result, started_at, finished_at) "
            "VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
            (p["mode"], p.get("status", "completed"), p.get("findings"), p.get("score"),
             p.get("result"), p["started_at"], p.get("finished_at")),
        )
    await db.commit()
    await db.close()
    return 1


def test_compare_returns_runs_chronological_with_parsed_fields(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "compare.db")
    _run(models.init_db())

    findings = [
        json.dumps([]),
        json.dumps([{"severity": "medium"}, {"severity": "low"}]),
        json.dumps([{"severity": "high"}, {"severity": "medium"}, {"severity": "low"}]),
    ]
    _run(_seed([
        {"mode": "fast", "findings": findings[0], "score": 10, "started_at": "2026-08-01T10:00:00"},
        {"mode": "deep", "findings": findings[1], "score": 50, "started_at": "2026-08-02T10:00:00"},
        {"mode": "full_depth", "findings": findings[2], "score": 30, "started_at": "2026-08-03T10:00:00"},
    ]))

    res = _run(main.compare_pipelines(target_id=1))

    assert res["target_id"] == 1
    assert res["target_name"] == "t"
    # Chronological ascending (oldest first), independent of insertion order
    started = [r["started_at"] for r in res["runs"]]
    assert started == sorted(started)
    # Parsed fields: score as int, findings_count from the JSON blob
    assert [r["score"] for r in res["runs"]] == [10, 50, 30]
    assert [r["findings_count"] for r in res["runs"]] == [0, 2, 3]
    # Raw findings blob is not leaked to the client
    assert all("findings" not in r for r in res["runs"])


def test_compare_unknown_target_is_404(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "compare.db")
    _run(models.init_db())

    with pytest.raises(HTTPException) as exc:
        _run(main.compare_pipelines(target_id=99))
    assert exc.value.status_code == 404


def test_compare_parses_legacy_rows_without_score_or_findings(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "compare.db")
    _run(models.init_db())

    # Pre-Fase-0.4 rows: findings/score NULL; plus one row with corrupted JSON
    _run(_seed([
        {"mode": "fast", "findings": None, "score": None, "started_at": "2026-07-01T10:00:00"},
        {"mode": "deep", "findings": "{corrupted", "score": 7, "started_at": "2026-07-02T10:00:00"},
    ]))

    res = _run(main.compare_pipelines(target_id=1))
    assert len(res["runs"]) == 2
    # NULL score stays null (frontend shows n/a); corrupted JSON does not break the endpoint
    assert res["runs"][0]["score"] is None
    assert res["runs"][0]["findings_count"] == 0
    assert res["runs"][1]["score"] == 7
    assert res["runs"][1]["findings_count"] == 0


def _finding(fid: str, severity: str = "medium", title: str = "") -> dict:
    return {"finding_id": fid, "severity": severity, "title": title or f"t-{fid}"}


def test_compare_delta_between_consecutive_runs(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "compare.db")
    _run(models.init_db())

    a = _finding("aaa111", "high", "HSTS missing")
    b = _finding("bbb222", "low", "Weak DKIM key")
    c = _finding("ccc333", "critical", "Exposed .git")
    _run(_seed([
        {"mode": "fast", "findings": json.dumps([a, b]), "score": 30,
         "started_at": "2026-08-01T10:00:00"},
        {"mode": "deep", "findings": json.dumps([a, c]), "score": 50,
         "started_at": "2026-08-02T10:00:00"},
        {"mode": "full_depth", "findings": json.dumps([c]), "score": 70,
         "started_at": "2026-08-03T10:00:00"},
    ]))

    res = _run(main.compare_pipelines(target_id=1))
    runs = res["runs"]

    # First run: baseline, all delta lists empty.
    assert runs[0]["new"] == [] and runs[0]["fixed"] == [] and runs[0]["persistent"] == []

    # Run 2 vs run 1: a persists, b is fixed, c is new.
    assert [it["finding_id"] for it in runs[1]["new"]] == ["ccc333"]
    assert [it["finding_id"] for it in runs[1]["fixed"]] == ["bbb222"]
    assert [it["finding_id"] for it in runs[1]["persistent"]] == ["aaa111"]
    # Display fields travel with each entry (no full evidence).
    assert runs[1]["new"][0] == {"finding_id": "ccc333", "severity": "critical",
                                "title": "Exposed .git"}

    # Run 3 vs run 2 (only adjacent runs are compared): a fixed, c persists.
    assert [it["finding_id"] for it in runs[2]["new"]] == []
    assert [it["finding_id"] for it in runs[2]["fixed"]] == ["aaa111"]
    assert [it["finding_id"] for it in runs[2]["persistent"]] == ["ccc333"]


def _jev_result(verdicts: dict, model: str = "jev-1.13.0") -> str:
    """A persisted result JSON whose jev block succeeded (Fase J)."""
    return json.dumps({
        "success": True,
        "score": 50,
        "jev": {"status": "ok", "model": model, "verdicts": verdicts},
    })


def test_compare_delta_carries_ai_verdicts_when_jev_ok(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "compare.db")
    _run(models.init_db())

    a = _finding("aaa111", "high", "HSTS missing")
    b = _finding("bbb222", "low", "Server banner")
    c = _finding("ccc333", "critical", "Exposed .git")
    jev1 = {
        "aaa111": {"verdict": "noise", "verdict_confidence": 0.9,
                   "severity_score": 0.5, "immediate_action": 0.1},
        "bbb222": {"verdict": "true_positive", "verdict_confidence": 0.8,
                   "severity_score": 1.0, "immediate_action": 0.3},
    }
    jev2 = {
        "aaa111": {"verdict": "true_positive", "verdict_confidence": 0.95,
                   "severity_score": 2.5, "immediate_action": 0.6},
        "ccc333": {"verdict": "false_positive", "verdict_confidence": 0.6,
                   "severity_score": 1.0, "immediate_action": 0.2},
    }
    _run(_seed([
        {"mode": "fast", "findings": json.dumps([a, b]), "score": 30,
         "result": _jev_result(jev1), "started_at": "2026-08-01T10:00:00"},
        {"mode": "deep", "findings": json.dumps([a, c]), "score": 50,
         "result": _jev_result(jev2), "started_at": "2026-08-02T10:00:00"},
    ]))

    res = _run(main.compare_pipelines(target_id=1))
    runs = res["runs"]
    assert runs[0]["new"] == [] and runs[0]["fixed"] == [] and runs[0]["persistent"] == []

    # New finding c carries the current run's verdict.
    assert runs[1]["new"][0]["ai_verdict"] == "false_positive"
    assert runs[1]["new"][0]["ai_confidence"] == 0.6
    # Fixed finding b carries the previous run's verdict (it is gone now).
    assert runs[1]["fixed"][0]["ai_verdict"] == "true_positive"
    assert runs[1]["fixed"][0]["ai_confidence"] == 0.8
    # Persistent finding a: prev -> cur, so the UI can flag the change.
    p = runs[1]["persistent"][0]
    assert p["ai_verdict_prev"] == "noise" and p["ai_confidence_prev"] == 0.9
    assert p["ai_verdict_cur"] == "true_positive" and p["ai_confidence_cur"] == 0.95


def test_compare_delta_ai_partial_when_only_one_run_has_jev(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "compare.db")
    _run(models.init_db())

    a = _finding("aaa111", "high", "HSTS missing")
    _run(_seed([
        {"mode": "fast", "findings": json.dumps([a]), "score": 30,
         "result": _jev_result({"aaa111": {"verdict": "noise",
                                            "verdict_confidence": 0.9}}),
         "started_at": "2026-08-01T10:00:00"},
        # Second run without any result (Jev disabled): persistent item keeps
        # the prev verdict only, never invents a cur one.
        {"mode": "deep", "findings": json.dumps([a]), "score": 50,
         "started_at": "2026-08-02T10:00:00"},
    ]))

    res = _run(main.compare_pipelines(target_id=1))
    p = res["runs"][1]["persistent"][0]
    assert p["ai_verdict_prev"] == "noise"
    assert "ai_verdict_cur" not in p and "ai_confidence_cur" not in p


def test_compare_delta_treats_null_and_corrupt_findings_as_empty_set(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "compare.db")
    _run(models.init_db())

    a = _finding("aaa111", "high")
    # NULL legacy row -> empty set; corrupted JSON -> empty set; then a real run.
    _run(_seed([
        {"mode": "fast", "findings": None, "score": None,
         "started_at": "2026-07-01T10:00:00"},
        {"mode": "deep", "findings": "{corrupted", "score": 5,
         "started_at": "2026-07-02T10:00:00"},
        {"mode": "full_depth", "findings": json.dumps([a]), "score": 40,
         "started_at": "2026-07-03T10:00:00"},
    ]))

    res = _run(main.compare_pipelines(target_id=1))
    runs = res["runs"]
    # NULL and corrupt rows stay empty sets without breaking the endpoint.
    assert runs[0]["new"] == [] and runs[0]["fixed"] == [] and runs[0]["persistent"] == []
    assert runs[1]["new"] == [] and runs[1]["fixed"] == [] and runs[1]["persistent"] == []
    # The first run with real findings is all-new against the empty set.
    assert [it["finding_id"] for it in runs[2]["new"]] == ["aaa111"]
    assert runs[2]["fixed"] == [] and runs[2]["persistent"] == []
