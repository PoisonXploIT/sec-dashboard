"""Fase 0.4: findings/score ride along with tool results and are persisted.

No network. Persistence is tested against a throwaway SQLite DB in tmp_path
by monkeypatching models.DB_PATH, so the real data/sec.db is never touched.
"""
import asyncio
import json

from backend import models, pipeline, scanner
from backend.findings import Finding, Severity, register


def _run(coro):
    return asyncio.run(coro)


@register("fase04_adapted_tool")
def _adapt_fase04(result: dict, target: str) -> list[Finding]:
    return [Finding(
        tool="fase04_adapted_tool", category="Web Security", severity=Severity.HIGH,
        title="Fake high finding", evidence={"k": "v"}, target=target, confidence=1.0,
    )]


def test_run_tool_with_adapter_returns_findings_and_score(monkeypatch):
    async def fake(target, **kw):
        return {"ok": True}

    monkeypatch.setitem(scanner.HANDLERS, "fase04_adapted_tool", fake)
    monkeypatch.setitem(scanner.TOOLS, "fase04_adapted_tool", {"timeout": 5})

    res = _run(scanner.run_tool("fase04_adapted_tool", "example.com"))
    assert res["success"] is True
    assert len(res["findings"]) == 1
    assert res["findings"][0]["severity"] == "high"
    # HIGH weight (7) * confidence 1.0
    assert res["score"] == 7


def test_run_tool_error_result_has_empty_findings(monkeypatch):
    async def boom(target, **kw):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(scanner.HANDLERS, "fase04_no_adapter", boom)
    monkeypatch.setitem(scanner.TOOLS, "fase04_no_adapter", {"timeout": 5})

    res = _run(scanner.run_tool("fase04_no_adapter", "example.com"))
    assert res["success"] is False
    assert res["findings"] == []
    assert res["score"] == 0


def test_unknown_tool_reports_empty_findings():
    res = _run(scanner.run_tool("no_such_tool_04", "example.com"))
    assert res["success"] is False
    assert res["findings"] == []
    assert res["score"] == 0


def test_persist_scan_result_stores_findings_and_score(tmp_path, monkeypatch):
    import backend.main as main

    dbfile = tmp_path / "fase04.db"
    monkeypatch.setattr(models, "DB_PATH", dbfile)

    _run(models.init_db())

    async def setup() -> int:
        db = await models.get_db()
        await db.execute("INSERT INTO targets (name, host) VALUES ('t', 'example.com')")
        cur = await db.execute(
            "INSERT INTO scans (target_id, tool, status) VALUES (1, 'header_analyzer', 'running')"
        )
        scan_id = cur.lastrowid
        await db.commit()
        await db.close()
        return scan_id

    scan_id = _run(setup())

    result = {
        "success": True,
        "tool": "header_analyzer",
        "findings": [{"severity": "medium", "confidence": 0.9, "title": "missing HSTS"}],
        "score": 4,
    }
    _run(main._persist_scan_result(scan_id, "completed", result))

    async def read():
        db = await models.get_db()
        cur = await db.execute("SELECT findings, score FROM scans WHERE id=?", (scan_id,))
        row = await cur.fetchone()
        await db.close()
        return row

    row = _run(read())
    assert json.loads(row["findings"]) == result["findings"]
    assert row["score"] == 4


def test_persist_pipeline_result_stores_aggregated_findings(tmp_path, monkeypatch):
    import backend.main as main

    dbfile = tmp_path / "fase04_pl.db"
    monkeypatch.setattr(models, "DB_PATH", dbfile)

    _run(models.init_db())

    async def setup() -> int:
        db = await models.get_db()
        await db.execute("INSERT INTO targets (name, host) VALUES ('t', 'example.com')")
        cur = await db.execute(
            "INSERT INTO pipelines (target_id, mode, status) VALUES (1, 'fast', 'running')"
        )
        pipeline_id = cur.lastrowid
        await db.commit()
        await db.close()
        return pipeline_id

    pipeline_id = _run(setup())

    findings_payload = [
        {"severity": "medium", "confidence": 1.0, "title": "a"},
        {"severity": "low", "confidence": 1.0, "title": "b"},
    ]
    result = {
        "status": "completed",
        "findings": findings_payload,
        "score": 6,
    }
    _run(main._persist_pipeline_result(pipeline_id, "completed", result))

    async def read():
        db = await models.get_db()
        cur = await db.execute(
            "SELECT findings, score FROM pipelines WHERE id=?", (pipeline_id,)
        )
        row = await cur.fetchone()
        await db.close()
        return row

    row = _run(read())
    assert json.loads(row["findings"]) == findings_payload
    assert row["score"] == 6


def test_pipeline_runner_aggregates_findings_and_score(monkeypatch):
    async def fake_run_tool(tool_name, target, **kw):
        n = int(tool_name[-1])
        return {
            "tool": tool_name,
            "target": target,
            "success": True,
            "elapsed_seconds": 0.01,
            "result": {},
            "findings": [{"severity": "medium", "confidence": 1.0, "title": f"f{n}"}],
            "score": 4,
        }

    monkeypatch.setitem(pipeline.PIPELINES, "fase04_test", {
        "phases": [{"name": "p1", "tools": ["t1", "t2"]}],
    })
    monkeypatch.setattr(pipeline, "run_tool", fake_run_tool)

    runner = pipeline.PipelineRunner(1, "fase04_test", "example.com")
    res = _run(runner.run())

    assert res["status"] == "completed"
    # Aggregated across both tools of the single phase
    assert len(res["findings"]) == 2
    # Two MEDIUM findings at confidence 1.0: 4 + 4
    assert res["score"] == 8
    # Per-tool findings are preserved inside each phase result too
    assert len(res["phases"]["p1"]["t1"]["findings"]) == 1
    assert len(res["phases"]["p1"]["t2"]["findings"]) == 1
