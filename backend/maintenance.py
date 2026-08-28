"""Retention purge + periodic DB backup (bunker phase, plan 2.3).

Both functions are pure w.r.t. the DB file and paths so tests can run them
against throwaway databases in tmp_path (Fase 0.4 pattern).
"""
import shutil
from datetime import datetime, timedelta
from pathlib import Path


async def purge_old_runs(db, retention_days: int) -> tuple[int, int]:
    """Delete scans/pipelines whose started_at is older than retention_days.

    Returns (scans_deleted, pipelines_deleted). retention_days <= 0 disables
    the purge (returns (0, 0) without touching the DB).
    """
    if retention_days <= 0:
        return (0, 0)
    cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
    cur = await db.execute("DELETE FROM scans WHERE started_at < ?", (cutoff,))
    n_scans = cur.rowcount
    cur = await db.execute(
        "DELETE FROM pipelines WHERE started_at < ?", (cutoff,)
    )
    n_pipelines = cur.rowcount
    await db.commit()
    return (n_scans, n_pipelines)


def backup_db(src: Path, backups_dir: Path, keep: int = 7) -> Path | None:
    """Copy the SQLite file into backups_dir with a UTC timestamp suffix.

    Prunes the oldest copies beyond `keep` (keep <= 0 disables pruning).
    Returns the destination path, or None when src does not exist.
    """
    if not src.exists():
        return None
    backups_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    dest = backups_dir / f"sec_{stamp}.db"
    shutil.copy2(src, dest)
    if keep > 0:
        files = sorted(backups_dir.glob("sec_*.db"))
        for old in files[:-keep]:
            old.unlink()
    return dest
