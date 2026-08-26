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
            "INSERT INTO pipelines (target_id, mode, status, findings, score, started_at, finished_at) "
            "VALUES (1, ?, ?, ?, ?, ?, ?)",
            (p["mode"], p.get("status", "completed"), p.get("findings"), p.get("score"),
             p["started_at"], p.get("finished_at")),
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
