"""Bulk delete-all endpoints + full statistics endpoint (Statistics page).

No network. Throwaway SQLite DB in tmp_path by monkeypatching models.DB_PATH
(Fase 0.4 pattern), so the real data/sec.db is never touched.
"""
import asyncio
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from backend import models


def _run(coro):
    return asyncio.run(coro)


class _FakeRequest:
    client = SimpleNamespace(host="127.0.0.1")
    headers = {"X-API-Key": "test-key-12345678"}


async def _seed() -> None:
    db = await models.get_db()
    await db.execute("INSERT INTO targets (name, host) VALUES ('a', 'a.com')")
    await db.execute("INSERT INTO targets (name, host) VALUES ('b', 'b.com')")
    result_ai = json.dumps({"jev": {"status": "ok"},
                            "llm_explanations": [{"title": "x"}]})
    for i in range(3):
        await db.execute(
            "INSERT INTO scans (target_id, tool, status, result, started_at) "
            "VALUES (?, 'tool_a', 'completed', ?, datetime('now', ?))",
            (1 if i % 2 else 2, result_ai if i == 0 else json.dumps({}),
             f"-{i} hours"))
    await db.execute(
        "INSERT INTO pipelines (target_id, mode, status, started_at, finished_at) "
        "VALUES (1, 'fast', 'completed', datetime('now','-1 hour'), datetime('now'))")
    await db.commit()
    await db.close()


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "stats.db")
    _run(models.init_db())
    _run(_seed())
    return main


def test_full_stats_totals_and_ai(seeded):
    s = _run(seeded.full_stats())
    assert s["total_targets"] == 2
    assert s["total_scans"] == 3
    assert s["total_pipelines"] == 1
    assert s["scans_by_status"] == {"completed": 3}
    assert s["pipelines_by_status"] == {"completed": 1}
    assert s["tools"] == [{"tool": "tool_a", "count": 3}]
    by_target = {t["name"]: t for t in s["by_target"]}
    # Seed: i=0->target b, i=1->target a, i=2->target b.
    assert by_target["a"]["scans"] == 1 and by_target["b"]["scans"] == 2
    assert by_target["a"]["pipelines"] == 1
    # AI usage: only one scan carries jev ok + llm_explanations.
    assert s["ai"]["scans_jev_ok"] == 1
    assert s["ai"]["scans_with_llm_explanations"] == 1
    assert s["ai"]["pipelines_jev_ok"] == 0
    assert len(s["daily_30d"]) == 30


def test_full_stats_pipeline_mode_avg(seeded):
    s = _run(seeded.full_stats())
    assert s["pipeline_modes"][0]["mode"] == "fast"
    assert s["pipeline_modes"][0]["count"] == 1
    assert s["pipeline_modes"][0]["avg_elapsed_seconds"] is not None


def test_delete_all_scans_requires_confirm(seeded):
    # confirm=False explicit: via HTTP FastAPI injects the real bool.
    with pytest.raises(HTTPException) as e:
        _run(seeded.delete_all_scans(confirm=False, request=_FakeRequest()))
    assert e.value.status_code == 400


def test_delete_all_scans_zeros_stats(seeded):
    res = _run(seeded.delete_all_scans(confirm=True, request=_FakeRequest()))
    assert res["deleted"] is True and res["count"] == 3
    s = _run(seeded.full_stats())
    assert s["total_scans"] == 0
    # Pipelines and targets are untouched.
    assert s["total_pipelines"] == 1 and s["total_targets"] == 2


def test_delete_all_targets_cascades(seeded):
    main = seeded
    _run(main.delete_all_scans(confirm=True, request=_FakeRequest))
    _run(main.delete_all_pipelines(confirm=True, request=_FakeRequest))
    _run(main.delete_all_targets(confirm=True, request=_FakeRequest))
    s = _run(main.full_stats())
    assert s["total_scans"] == 0
    assert s["total_pipelines"] == 0
    assert s["total_targets"] == 0
