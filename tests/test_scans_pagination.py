"""Paginación server-side: GET /api/scans page/per_page.

No network. Uses a throwaway SQLite DB in tmp_path by monkeypatching
models.DB_PATH (Fase 0.4 pattern), so the real data/sec.db is never touched.
"""
import asyncio

from backend import models


def _run(coro):
    return asyncio.run(coro)


async def _seed():
    db = await models.get_db()
    for name, host in [("web", "example.com"), ("db", "db.example.com")]:
        cur = await db.execute("INSERT INTO targets (name, host) VALUES (?, ?)", (name, host))
        target_id = cur.lastrowid
        rows = [
            ("nmap", "completed", 1, "2026-08-01T10:00:00"),
            ("masscan", "running", 1, "2026-08-02T10:00:00"),
            ("nuclei", "failed", 1, "2026-08-03T10:00:00"),
        ]
        for tool, status, score, started in rows:
            await db.execute(
                "INSERT INTO scans (target_id, tool, status, result, findings, score, started_at) "
                "VALUES (?, ?, ?, NULL, '[]', ?, ?)",
                (target_id, tool, status, score, started),
            )
    await db.commit()
    await db.close()


def _setup(tmp_path, monkeypatch):
    import backend.main as main

    monkeypatch.setattr(models, "DB_PATH", tmp_path / "scans.db")
    _run(models.init_db())
    _run(_seed())
    return main


def test_default_page_envelope_and_order(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    res = _run(main.list_scans())
    assert res["page"] == 1 and res["per_page"] == 50
    assert res["total"] == 6
    # Newest first across both targets
    assert [s["started_at"] for s in res["scans"]] == sorted(
        [s["started_at"] for s in res["scans"]], reverse=True
    )
    # Join still present
    assert all(s["target_name"] in ("web", "db") for s in res["scans"])


def test_per_page_slices_desc(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    p1 = _run(main.list_scans(page=1, per_page=2))
    assert (p1["page"], p1["per_page"], p1["total"]) == (1, 2, 6)
    p2 = _run(main.list_scans(page=2, per_page=2))
    p3 = _run(main.list_scans(page=3, per_page=2))
    assert len(p1["scans"]) == 2 and len(p2["scans"]) == 2 and len(p3["scans"]) == 2
    # No overlap, no gaps: concatenation equals the full desc list
    all_rows = _run(main.list_scans(per_page=6))["scans"]
    assert [s["id"] for s in p1["scans"] + p2["scans"] + p3["scans"]] == [
        s["id"] for s in all_rows
    ]


def test_target_id_filter_counts_only_that_target(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    res = _run(main.list_scans(target_id=1, per_page=2))
    assert res["total"] == 3
    assert all(s["target_name"] == "web" for s in res["scans"])


def test_clamping_page_and_per_page(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    # page below 1 clamps to 1 (not a negative offset)
    res = _run(main.list_scans(page=0))
    assert res["page"] == 1 and len(res["scans"]) > 0
    # per_page capped at 200, echoed in the envelope
    res = _run(main.list_scans(per_page=9999))
    assert res["per_page"] == 200
