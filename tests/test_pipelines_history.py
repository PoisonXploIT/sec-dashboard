"""3E sub-micro-paso 3: GET /api/pipelines/history filters (mode/status/q).

No network. Uses a throwaway SQLite DB in tmp_path by monkeypatching
models.DB_PATH (Fase 0.4 pattern), so the real data/sec.db is never touched.
"""
import asyncio

from backend import models


def _run(coro):
    return asyncio.run(coro)


async def _seed():
    db = await models.get_db()
    await db.execute("INSERT INTO targets (name, host) VALUES ('web', 'example.com')")
    rows = [
        ("fast", "completed", 1, "2026-08-01T10:00:00"),
        ("deep", "completed", 1, "2026-08-02T10:00:00"),
        ("nuclear", "failed", 1, "2026-08-03T10:00:00"),
    ]
    for mode, status, target_id, started in rows:
        await db.execute(
            "INSERT INTO pipelines (target_id, mode, status, findings, score, started_at) "
            "VALUES (?, ?, ?, '[]', 0, ?)",
            (target_id, mode, status, started),
        )
    await db.commit()
    await db.close()


def _setup(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "history.db")
    _run(models.init_db())
    _run(_seed())
    return main


def test_no_filters_returns_all_desc(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    res = _run(main.pipeline_history())
    pipes = res["pipelines"]
    assert len(pipes) == 3
    # Newest first, and the target join is present
    assert [p["started_at"] for p in pipes] == sorted(
        [p["started_at"] for p in pipes], reverse=True
    )
    assert all(p["target_name"] == "web" and p["target_host"] == "example.com" for p in pipes)


def test_mode_and_status_exact_filters(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    res = _run(main.pipeline_history(mode="deep"))
    assert [p["mode"] for p in res["pipelines"]] == ["deep"]

    res = _run(main.pipeline_history(status="failed"))
    assert [p["mode"] for p in res["pipelines"]] == ["nuclear"]

    # Combined: no row matches both -> empty, not an error
    res = _run(main.pipeline_history(mode="fast", status="failed"))
    assert res["pipelines"] == []


def test_q_searches_mode_target_name_and_host(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    # Host match
    res = _run(main.pipeline_history(q="example"))
    assert len(res["pipelines"]) == 3
    # Mode match (case-insensitive LIKE on ASCII)
    res = _run(main.pipeline_history(q="DEEP"))
    assert [p["mode"] for p in res["pipelines"]] == ["deep"]
    # Target name match
    res = _run(main.pipeline_history(q="web"))
    assert len(res["pipelines"]) == 3
    # No match
    res = _run(main.pipeline_history(q="no-such-thing"))
    assert res["pipelines"] == []
