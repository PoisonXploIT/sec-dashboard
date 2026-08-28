"""Retention + backup (bunker 2.3): purge_old_runs y backup_db.

Sin red. DB throwaway en tmp_path (patron Fase 0.4) via aiosqlite directo,
mismo estilo de llamada que test_compare_endpoint.py.
"""
import asyncio

from backend import models
from backend.maintenance import purge_old_runs, backup_db


def _run(coro):
    return asyncio.run(coro)


async def _seed(rows_scans, rows_pipelines):
    # get_db() sets PRAGMA foreign_keys=ON, so the scans/pipelines need a
    # real targets row to reference (fresh DB: first insert is id 1).
    db = await models.get_db()
    try:
        cur = await db.execute("INSERT INTO targets (name, host) VALUES ('t', 'h')")
        target_id = cur.lastrowid
        for started in rows_scans:
            await db.execute(
                "INSERT INTO scans (target_id, tool, status, started_at) VALUES (?, 't', 'completed', ?)",
                (target_id, started),
            )
        for started in rows_pipelines:
            await db.execute(
                "INSERT INTO pipelines (target_id, mode, status, started_at) VALUES (?, 'fast', 'completed', ?)",
                (target_id, started),
            )
        await db.commit()
    finally:
        # Always close: an unclosed aiosqlite connection keeps its worker
        # thread alive and hangs pytest at exit.
        await db.close()


def test_purge_deletes_only_old_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(models, "DB_PATH", tmp_path / "purge.db")
    _run(models.init_db())
    _run(_seed(["2020-01-01T00:00:00", "2020-06-01T00:00:00", "2099-01-01T00:00:00"],
               ["2020-03-01T00:00:00", "2099-01-01T00:00:00"]))

    async def _purge_and_count():
        db = await models.get_db()
        try:
            n_scans, n_pipelines = await purge_old_runs(db, 30)
            cur = await db.execute("SELECT COUNT(*) FROM scans")
            left_scans = (await cur.fetchone())[0]
            cur = await db.execute("SELECT COUNT(*) FROM pipelines")
            left_pipelines = (await cur.fetchone())[0]
        finally:
            await db.close()
        return n_scans, n_pipelines, left_scans, left_pipelines

    n_scans, n_pipelines, left_scans, left_pipelines = _run(_purge_and_count())
    assert (n_scans, n_pipelines) == (2, 1)
    assert (left_scans, left_pipelines) == (1, 1)


def test_purge_disabled_at_zero_days(tmp_path, monkeypatch):
    monkeypatch.setattr(models, "DB_PATH", tmp_path / "purge0.db")
    _run(models.init_db())
    _run(_seed(["2020-01-01T00:00:00"], ["2020-01-01T00:00:00"]))

    async def _check():
        db = await models.get_db()
        try:
            res = await purge_old_runs(db, 0)
            cur = await db.execute("SELECT COUNT(*) FROM scans")
            left = (await cur.fetchone())[0]
        finally:
            await db.close()
        return res, left

    res, left = _run(_check())
    assert res == (0, 0)
    assert left == 1


def test_backup_copies_and_prunes(tmp_path):
    src = tmp_path / "sec.db"
    src.write_bytes(b"sqlite-bytes")
    dest = backup_db(src, tmp_path / "backups", keep=2)
    assert dest is not None and dest.exists()

    # Rellenar historico: dos copias mas viejas de la real.
    (tmp_path / "backups" / "sec_20260101_000000.db").write_bytes(b"old1")
    (tmp_path / "backups" / "sec_20260102_000000.db").write_bytes(b"old2")
    dest2 = backup_db(src, tmp_path / "backups", keep=2)
    files = sorted((tmp_path / "backups").glob("sec_*.db"))
    # Con keep=2 solo quedan las dos mas recientes.
    assert len(files) == 2
    assert files[-1] == dest2


def test_backup_missing_src_returns_none(tmp_path):
    assert backup_db(tmp_path / "nope.db", tmp_path / "backups") is None
