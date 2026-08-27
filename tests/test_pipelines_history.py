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


def test_pagination_envelope_and_slices(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    p1 = _run(main.pipeline_history(page=1, per_page=2))
    assert (p1["page"], p1["per_page"], p1["total"]) == (1, 2, 3)
    assert len(p1["pipelines"]) == 2
    p2 = _run(main.pipeline_history(page=2, per_page=2))
    assert len(p2["pipelines"]) == 1
    # No overlap between pages
    assert p1["pipelines"][0]["id"] != p2["pipelines"][0]["id"]
    # Page beyond the end: empty, not an error
    p4 = _run(main.pipeline_history(page=4, per_page=2))
    assert p4["pipelines"] == [] and p4["total"] == 3


def test_pagination_interacts_with_filters(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    # total reflects the filter, not the whole table
    res = _run(main.pipeline_history(mode="deep", per_page=1))
    assert res["total"] == 1 and len(res["pipelines"]) == 1
    res = _run(main.pipeline_history(q="example", per_page=2))
    assert res["total"] == 3 and len(res["pipelines"]) == 2


def test_pagination_clamping(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    # page below 1 clamps to 1 (not a negative offset)
    res = _run(main.pipeline_history(page=0))
    assert res["page"] == 1 and len(res["pipelines"]) > 0
    # per_page capped at 200, echoed in the envelope
    res = _run(main.pipeline_history(per_page=9999))
    assert res["per_page"] == 200
