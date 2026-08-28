"""FastAPI backend — REST API + WebSocket for real-time updates."""
import asyncio
import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.config import (
    TOOLS, CATEGORIES, PIPELINES, RESULTS_DIR, SPECIAL_TOOLS,
    DATA_DIR, DB_PATH,
)
from backend.models import init_db, get_db
from backend.scanner import run_tool, run_parallel
from backend.pipeline import PipelineRunner
from backend.proxy import get_proxy_config, set_proxy_config, get_tor_status, get_aiohttp_proxy
from backend.report import (
    generate_scan_json, generate_pipeline_json, generate_all_json,
    generate_scan_pdf, generate_pipeline_pdf, generate_all_pdf,
    generate_executive_pdf,
    generate_scan_csv, generate_pipeline_csv,
)
from backend.validators import validate_target, is_remote_mode
from backend.ratelimit import RateLimiter
from backend.authguard import FailedAuthTracker, truncate_key
from backend.maintenance import purge_old_runs, backup_db
from backend import webhooks
from backend import splunk
from backend.applog import get_logger, setup_logging

# Structured logging: rotating file (data/logs) + stdout, before anything runs.
setup_logging()
_log = get_logger("main")

app = FastAPI(title="Sec-Dashboard", version="1.0.0")

_same_origin = ["http://localhost:8444", "http://127.0.0.1:8444"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_same_origin + (["https://sec.sammideblas.com"] if is_remote_mode() else []),
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API key auth (C2) ─────────────────────────────────────────
# If SEC_DASHBOARD_API_KEY is set, every /api/* request must send
# header X-API-Key (or ?key= for the WebSocket). Unset = open (local use).
# Cloudflare Access (portfolio mode): requests that already passed the
# Access policy carry Cf-Access-Authenticated-User-Email (injected by
# Cloudflare, only reachable through it) and are allowed without a key.
API_KEY = os.environ.get("SEC_DASHBOARD_API_KEY", "")

# Lockout after repeated failed auth (bunker 2.1): N failures inside a window
# ban the peer for `lockout` seconds. Env-tunable; defaults 5 / 300s / 900s.
_AUTH_MAX_FAILURES = int(os.environ.get("SEC_AUTH_MAX_FAILURES", "5"))
_AUTH_FAILURE_WINDOW = float(os.environ.get("SEC_AUTH_FAILURE_WINDOW", "300"))
_AUTH_LOCKOUT_SECONDS = float(os.environ.get("SEC_AUTH_LOCKOUT", "900"))
_auth_lockout = FailedAuthTracker(
    _AUTH_MAX_FAILURES, _AUTH_FAILURE_WINDOW, _AUTH_LOCKOUT_SECONDS
)


def _passed_cloudflare_access(request: Request) -> bool:
    """True if Cloudflare Access authenticated this request (SSO login)."""
    return bool(request.headers.get("Cf-Access-Authenticated-User-Email"))


@app.middleware("http")
async def require_api_key(request: Request, call_next):
    if API_KEY and request.url.path.startswith("/api"):
        # Let CORS preflight through so the browser can negotiate
        if request.method != "OPTIONS":
            peer = request.client.host if request.client else "?"
            blocked, retry_after = _auth_lockout.is_blocked(peer)
            if blocked:
                return JSONResponse(
                    {"detail": "Too many failed auth attempts; temporarily blocked"},
                    status_code=403,
                    headers={"Retry-After": str(retry_after)},
                )
            presented = request.headers.get("X-API-Key", "")
            if _passed_cloudflare_access(request):
                pass  # Cloudflare Access already authenticated this request
            elif presented == API_KEY:
                _auth_lockout.record_success(peer)
                _log.debug(
                    "auth ok ip=%s key=%s path=%s",
                    peer, truncate_key(presented), request.url.path,
                )
            else:
                _auth_lockout.record_failure(peer)
                # Audit: every failed attempt, key truncated (never full).
                _log.warning(
                    "auth failed ip=%s key=%s path=%s",
                    peer, truncate_key(presented), request.url.path,
                )
                return JSONResponse({"detail": "Invalid or missing API key"}, status_code=401)
    return await call_next(request)


# ── Rate limiting (in-memory, no Redis) ───────────────────────
# Strict bucket for the expensive mutation POSTs (30 req/min per IP) and a
# much more permissive flood guard for GETs (the UI polls every ~2s while a
# run is in progress). Keyed by direct peer only: X-Forwarded-For is NOT
# trusted — a spoofable header would let an attacker mint fresh buckets by
# rotating its value. Behind Cloudflare this degrades to per-origin
# granularity, which still caps the total mutation rate of the deployment.
MUTATION_RATE_LIMIT = 30   # req/min per IP on POST /api/scans|pipelines|targets
READ_RATE_LIMIT = 600      # req/min per IP on GET /api/*

_mutation_limiter = RateLimiter(MUTATION_RATE_LIMIT)
_read_limiter = RateLimiter(READ_RATE_LIMIT)
# Per-API-key buckets (bunker 2.1): fairer than per-IP behind Cloudflare,
# where one origin IP is shared by every client. Keyed by sha256 of the
# presented key so the raw secret never lands in memory beyond the hash.
_key_mutation_limiter = RateLimiter(MUTATION_RATE_LIMIT)
_key_read_limiter = RateLimiter(READ_RATE_LIMIT)

_MUTATION_PATHS = {"/api/scans", "/api/pipelines", "/api/targets"}


def _rate_limit_bucket(method: str, path: str):
    """Return the limiter bucket for a request, or None if unlimited."""
    if method == "POST" and path in _MUTATION_PATHS:
        return _mutation_limiter
    if method == "GET" and path.startswith("/api/"):
        return _read_limiter
    return None


def _key_rate_limit_bucket(method: str, path: str):
    """Per-key bucket; None when auth is off or the request carries no key."""
    if not API_KEY:
        return None
    if method == "POST" and path in _MUTATION_PATHS:
        return _key_mutation_limiter
    if method == "GET" and path.startswith("/api/"):
        return _key_read_limiter
    return None


def _rate_limit_key(request: Request) -> str:
    return request.client.host if request.client else "?"


def _key_rate_limit_id(request: Request):
    presented = request.headers.get("X-API-Key", "")
    if not presented:
        return None  # missing key: auth answers 401, IP bucket still caps it
    return "k:" + hashlib.sha256(presented.encode()).hexdigest()[:32]


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    # Defined after require_api_key, so it is outermost and runs first:
    # floods are capped before any auth work happens.
    bucket = _rate_limit_bucket(request.method, request.url.path)
    if bucket is not None:
        allowed, retry_after = bucket.check(_rate_limit_key(request))
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
    key_bucket = _key_rate_limit_bucket(request.method, request.url.path)
    if key_bucket is not None:
        key_id = _key_rate_limit_id(request)
        if key_id is not None:
            allowed, retry_after = key_bucket.check(key_id)
            if not allowed:
                return JSONResponse(
                    {"detail": "Rate limit exceeded for this API key"},
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                )
    return await call_next(request)


# -- Proxy / Anonymity -----------------------------------------
class ProxyConfig(BaseModel):
    enabled: bool = False
    type: str = "none"  # none, tor, socks5, socks4
    host: str = "127.0.0.1"
    port: int = 9050
    username: str = ""
    password: str = ""

@app.get("/api/proxy")
async def get_proxy():
    config = get_proxy_config()
    config["password"] = "***" if config.get("password") else ""
    # L3: TOR detection does blocking socket connects -- run off the event loop
    tor = await asyncio.to_thread(get_tor_status)
    return {"config": config, "tor_status": tor}

@app.post("/api/proxy")
async def update_proxy(body: ProxyConfig):
    config = body.dict()
    # Don't overwrite password if masked
    if config.get("password") == "***":
        config["password"] = get_proxy_config().get("password", "")
    set_proxy_config(config)
    config = get_proxy_config()
    config["password"] = "***" if config.get("password") else ""
    return {"status": "updated", "config": config}

@app.get("/api/proxy/tor-ip")
async def get_tor_exit_ip():
    from backend.proxy import get_aiohttp_connector
    connector = get_aiohttp_connector()
    if not connector:
        return {"error": "Proxy not enabled or TOR not running"}
    try:
        import aiohttp
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.get("https://httpbin.org/ip") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"tor_ip": data.get("origin", "unknown"), "status": "connected"}
                return {"error": f"Status {resp.status}"}
    except Exception as e:
        return {"error": str(e)[:100]}

@app.get("/api/proxy/tor-install")
async def tor_install_guide():
    return {
        "platform": "Windows",
        "options": [
            {
                "name": "TOR Browser (easiest)",
                "steps": [
                    "Download from https://www.torproject.org/download/",
                    "Install and run TOR Browser",
                    "SOCKS5 proxy will be available on 127.0.0.1:9150",
                    "Set proxy port to 9150 in sec-dashboard proxy settings",
                ],
                "note": "TOR Browser must be running for proxy to work",
            },
            {
                "name": "TOR Expert Bundle (headless)",
                "steps": [
                    "Download from https://www.torproject.org/download/tor/",
                    "Extract and run tor.exe",
                    "SOCKS5 proxy on 127.0.0.1:9050 (default)",
                    "Works without TOR Browser",
                ],
            },
        ],
        "after_install": "Go to Proxy settings in sec-dashboard and enable TOR",
    }


# -- Export / Reports ------------------------------------------
from fastapi.responses import Response as FastResponse

@app.get("/api/scans/{scan_id}/export/json")
async def export_scan_json(scan_id: int):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(404, "Scan not found")
        scan = dict(scan)
        target = None
        if scan.get("target_id"):
            cur2 = await db.execute("SELECT * FROM targets WHERE id = ?", (scan["target_id"],))
            row = await cur2.fetchone()
            if row: target = dict(row)
        content = generate_scan_json(scan, target)
        return HTMLResponse(content=content, media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.json"'})
    finally:
        await db.close()

@app.get("/api/scans/{scan_id}/export/pdf")
async def export_scan_pdf(scan_id: int):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(404, "Scan not found")
        scan = dict(scan)
        target = None
        if scan.get("target_id"):
            cur2 = await db.execute("SELECT * FROM targets WHERE id = ?", (scan["target_id"],))
            row = await cur2.fetchone()
            if row: target = dict(row)
        pdf_bytes = generate_scan_pdf(scan, target)
        return FastResponse(content=pdf_bytes, media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.pdf"'})
    finally:
        await db.close()

@app.get("/api/scans/{scan_id}/export/csv")
async def export_scan_csv(scan_id: int):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = await cursor.fetchone()
        if not scan:
            raise HTTPException(404, "Scan not found")
        scan = dict(scan)
        target = None
        if scan.get("target_id"):
            cur2 = await db.execute("SELECT * FROM targets WHERE id = ?", (scan["target_id"],))
            row = await cur2.fetchone()
            if row: target = dict(row)
        content = generate_scan_csv(scan, target)
        return FastResponse(content=content.encode("utf-8"), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.csv"'})
    finally:
        await db.close()

@app.get("/api/pipelines/{pipeline_id}/export/json")
async def export_pipeline_json(pipeline_id: int):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM pipelines WHERE id = ?", (pipeline_id,))
        pipeline = await cursor.fetchone()
        if not pipeline:
            raise HTTPException(404, "Pipeline not found")
        pipeline = dict(pipeline)
        target = None
        if pipeline.get("target_id"):
            cur2 = await db.execute("SELECT * FROM targets WHERE id = ?", (pipeline["target_id"],))
            row = await cur2.fetchone()
            if row: target = dict(row)
        content = generate_pipeline_json(pipeline, target)
        return HTMLResponse(content=content, media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="pipeline_{pipeline_id}.json"'})
    finally:
        await db.close()

@app.get("/api/pipelines/{pipeline_id}/export/pdf")
async def export_pipeline_pdf_endpoint(pipeline_id: int):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM pipelines WHERE id = ?", (pipeline_id,))
        pipeline = await cursor.fetchone()
        if not pipeline:
            raise HTTPException(404, "Pipeline not found")
        pipeline = dict(pipeline)
        target = None
        if pipeline.get("target_id"):
            cur2 = await db.execute("SELECT * FROM targets WHERE id = ?", (pipeline["target_id"],))
            row = await cur2.fetchone()
            if row: target = dict(row)
        pdf_bytes = generate_pipeline_pdf(pipeline, target)
        return FastResponse(content=pdf_bytes, media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="pipeline_{pipeline_id}.pdf"'})
    finally:
        await db.close()

@app.get("/api/pipelines/{pipeline_id}/export/csv")
async def export_pipeline_csv(pipeline_id: int):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM pipelines WHERE id = ?", (pipeline_id,))
        pipeline = await cursor.fetchone()
        if not pipeline:
            raise HTTPException(404, "Pipeline not found")
        pipeline = dict(pipeline)
        target = None
        if pipeline.get("target_id"):
            cur2 = await db.execute("SELECT * FROM targets WHERE id = ?", (pipeline["target_id"],))
            row = await cur2.fetchone()
            if row: target = dict(row)
        content = generate_pipeline_csv(pipeline, target)
        return FastResponse(content=content.encode("utf-8"), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="pipeline_{pipeline_id}.csv"'})
    finally:
        await db.close()

@app.get("/api/pipelines/{pipeline_id}/executive-pdf")
async def export_pipeline_executive_pdf_endpoint(pipeline_id: int):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM pipelines WHERE id = ?", (pipeline_id,))
        pipeline = await cursor.fetchone()
        if not pipeline:
            raise HTTPException(404, "Pipeline not found")
        pipeline = dict(pipeline)
        target = None
        if pipeline.get("target_id"):
            cur2 = await db.execute("SELECT * FROM targets WHERE id = ?", (pipeline["target_id"],))
            row = await cur2.fetchone()
            if row: target = dict(row)
        pdf_bytes = generate_executive_pdf(pipeline, target)
        return FastResponse(content=pdf_bytes, media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="pipeline_{pipeline_id}_executive.pdf"'})
    finally:
        await db.close()

@app.get("/api/export/all/json")
async def export_all_json_endpoint():
    db = await get_db()
    try:
        cur_s = await db.execute("SELECT * FROM scans ORDER BY started_at DESC")
        scans = [dict(r) for r in await cur_s.fetchall()]
        cur_p = await db.execute("SELECT * FROM pipelines ORDER BY started_at DESC")
        pipelines = [dict(r) for r in await cur_p.fetchall()]
        cur_t = await db.execute("SELECT * FROM targets")
        targets = [dict(r) for r in await cur_t.fetchall()]
        content = generate_all_json(scans, pipelines, targets)
        return HTMLResponse(content=content, media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="sec-dashboard-export.json"'})
    finally:
        await db.close()


@app.get("/api/export/all/pdf")
async def export_all_pdf_endpoint():
    db = await get_db()
    try:
        cur_s = await db.execute("SELECT * FROM scans ORDER BY started_at DESC")
        scans = [dict(r) for r in await cur_s.fetchall()]
        cur_p = await db.execute("SELECT * FROM pipelines ORDER BY started_at DESC")
        pipelines = [dict(r) for r in await cur_p.fetchall()]
        cur_t = await db.execute("SELECT * FROM targets")
        targets = [dict(r) for r in await cur_t.fetchall()]
        pdf_bytes = generate_all_pdf(scans, pipelines, targets)
        return FastResponse(content=pdf_bytes, media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="sec-dashboard-export.pdf"'})
    finally:
        await db.close()


# ── WebSocket connections ──────────────────────────────────────
ws_clients: set[WebSocket] = set()

# Track running scans and pipelines for cancellation
_running_scans: dict[int, asyncio.Task] = {}
_running_pipelines: dict[int, asyncio.Task] = {}


async def broadcast(event: dict):
    """Send event to all connected WebSocket clients."""
    dead = set()
    for ws in ws_clients:
        try:
            await ws.send_json(event)
        except Exception:
            dead.add(ws)
    ws_clients.difference_update(dead)


# ── Pydantic schemas ──────────────────────────────────────────
class TargetCreate(BaseModel):
    name: str
    host: str

class ScanCreate(BaseModel):
    target_id: int = 0  # 0 = no target (special tools)
    tool: str
    params: dict = {}
    direct_input: str = ""  # For special tools
    wait: bool = True  # False = return immediately, poll GET /api/scans/{id}

class PipelineCreate(BaseModel):
    target_id: int
    mode: str

class ToolRun(BaseModel):
    target: str
    params: dict = {}
    direct_input: str = ""  # For special tools (hash, password, keyword)


# ── Events ────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    await init_db()
    # Migrate: make scans.target_id nullable for special tools
    db = await get_db()
    try:
        # Check if target_id is nullable
        cur = await db.execute("PRAGMA table_info(scans)")
        cols = await cur.fetchall()
        target_col = [c for c in cols if c["name"] == "target_id"]
        if target_col and target_col[0]["notnull"] == 1:
            # Need to recreate the table with nullable target_id
            await db.execute("PRAGMA foreign_keys=OFF")
            await db.execute("ALTER TABLE scans RENAME TO scans_old")
            await db.execute(
                "CREATE TABLE scans ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "target_id INTEGER, "
                "tool TEXT NOT NULL, "
                "status TEXT DEFAULT 'pending', "
                "result TEXT, "
                "started_at TIMESTAMP, "
                "finished_at TIMESTAMP, "
                "FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE"
                ")"
            )
            await db.execute("INSERT INTO scans SELECT * FROM scans_old")
            await db.execute("DROP TABLE scans_old")
            await db.execute("PRAGMA foreign_keys=ON")
            await db.commit()
            _log.info("Migrated scans table: target_id is now nullable")
    except Exception as e:
        _log.warning("scans migration check failed: %s", e)
    finally:
        await db.close()

    # Migrate (Fase 0.4): add findings + score columns to scans
    db = await get_db()
    try:
        cur = await db.execute("PRAGMA table_info(scans)")
        cols = {c["name"] for c in await cur.fetchall()}
        if "findings" not in cols:
            await db.execute("PRAGMA foreign_keys=OFF")
            await db.execute("ALTER TABLE scans RENAME TO scans_old")
            await db.execute(
                "CREATE TABLE scans ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "target_id INTEGER, "
                "tool TEXT NOT NULL, "
                "status TEXT DEFAULT 'pending', "
                "result TEXT, "
                "findings TEXT DEFAULT '[]', "
                "score INTEGER DEFAULT 0, "
                "started_at TIMESTAMP, "
                "finished_at TIMESTAMP, "
                "FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE"
                ")"
            )
            await db.execute(
                "INSERT INTO scans (id, target_id, tool, status, result, started_at, finished_at) "
                "SELECT id, target_id, tool, status, result, started_at, finished_at FROM scans_old"
            )
            await db.execute("DROP TABLE scans_old")
            await db.execute("PRAGMA foreign_keys=ON")
            await db.commit()
            _log.info("Migrated scans table: added findings + score columns")
    except Exception as e:
        _log.warning("scans findings migration check failed: %s", e)
    finally:
        await db.close()

    # Migrate (Fase 0.4): add findings + score columns to pipelines
    db = await get_db()
    try:
        cur = await db.execute("PRAGMA table_info(pipelines)")
        cols = {c["name"] for c in await cur.fetchall()}
        if "findings" not in cols:
            await db.execute("PRAGMA foreign_keys=OFF")
            await db.execute("ALTER TABLE pipelines RENAME TO pipelines_old")
            await db.execute(
                "CREATE TABLE pipelines ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "target_id INTEGER NOT NULL, "
                "mode TEXT NOT NULL, "
                "status TEXT DEFAULT 'pending', "
                "progress REAL DEFAULT 0.0, "
                "current_phase TEXT, "
                "current_tool TEXT, "
                "result TEXT, "
                "findings TEXT DEFAULT '[]', "
                "score INTEGER DEFAULT 0, "
                "started_at TIMESTAMP, "
                "finished_at TIMESTAMP, "
                "FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE"
                ")"
            )
            await db.execute(
                "INSERT INTO pipelines (id, target_id, mode, status, progress, current_phase, "
                "current_tool, result, started_at, finished_at) "
                "SELECT id, target_id, mode, status, progress, current_phase, "
                "current_tool, result, started_at, finished_at FROM pipelines_old"
            )
            await db.execute("DROP TABLE pipelines_old")
            await db.execute("PRAGMA foreign_keys=ON")
            await db.commit()
            _log.info("Migrated pipelines table: added findings + score columns")
    except Exception as e:
        _log.warning("pipelines findings migration check failed: %s", e)
    finally:
        await db.close()

    # Clean up orphaned scans left as 'running' from a previous crash/restart
    db = await get_db()
    try:
        cur = await db.execute(
            "UPDATE scans SET status = 'failed', result = ?, finished_at = ? "
            "WHERE status = 'running'",
            (json.dumps({"error": "Server restarted while scan was running", "success": False}),
             datetime.utcnow().isoformat())
        )
        if cur.rowcount:
            await db.commit()
            _log.info("Marked %d orphaned running scans as failed", cur.rowcount)
    finally:
        await db.close()
    # Retention + backup (bunker 2.3): purge runs/pipelines older than
    # SEC_DASHBOARD_RETENTION_DAYS (0 disables) and copy the DB to
    # data/backups keeping SEC_DASHBOARD_BACKUP_KEEP copies. First pass here,
    # then every 6h.
    retention_days = int(os.environ.get("SEC_DASHBOARD_RETENTION_DAYS", "30"))
    backup_keep = int(os.environ.get("SEC_DASHBOARD_BACKUP_KEEP", "7"))
    asyncio.create_task(_maintenance_loop(retention_days, backup_keep))

    _log.info("startup complete: %d tools registered, remote_mode=%s", len(TOOLS), is_remote_mode())


async def _maintenance_loop(retention_days: int, backup_keep: int):
    """Hourly-ish maintenance pass: retention purge + DB backup."""
    while True:
        try:
            db = await get_db()
            try:
                n_scans, n_pipelines = await purge_old_runs(db, retention_days)
                if n_scans or n_pipelines:
                    _log.info("retention purged scans=%d pipelines=%d", n_scans, n_pipelines)
            finally:
                await db.close()
            dest = backup_db(DB_PATH, DATA_DIR / "backups", backup_keep)
            if dest:
                _log.info("db backup written %s", dest.name)
        except Exception:
            _log.exception("maintenance pass failed")
        await asyncio.sleep(6 * 3600)


# ── Health ─────────────────────────────────────────────────────
@app.get("/api/status")
async def status():
    return {
        "status": "ok",
        "version": "1.0.0",
        "tools_count": len(TOOLS),
        "categories": CATEGORIES,
        "uptime": int(time.time() - START_TIME),  # L2: real uptime, not epoch
        "remote_mode": is_remote_mode(),
    }


# -- Dashboard Stats -------------------------------------------
START_TIME = time.time()

@app.get("/api/dashboard/stats")
async def dashboard_stats():
    db = await get_db()
    try:
        # Total counts
        cur = await db.execute("SELECT COUNT(*) as c FROM targets")
        total_targets = (await cur.fetchone())["c"]

        cur = await db.execute("SELECT COUNT(*) as c FROM scans")
        total_scans = (await cur.fetchone())["c"]

        cur = await db.execute("SELECT COUNT(*) as c FROM pipelines")
        total_pipelines = (await cur.fetchone())["c"]

        # Scans by status
        cur = await db.execute("SELECT status, COUNT(*) as c FROM scans GROUP BY status")
        scans_by_status = {r["status"]: r["c"] for r in await cur.fetchall()}

        # Scans by tool (top 10)
        cur = await db.execute(
            "SELECT tool, COUNT(*) as c FROM scans GROUP BY tool ORDER BY c DESC LIMIT 10"
        )
        scans_by_tool = [{"tool": r["tool"], "count": r["c"]} for r in await cur.fetchall()]

        # Recent scans (last 10)
        cur = await db.execute(
            "SELECT s.id, s.tool, s.status, s.started_at, s.finished_at, "
            "t.name as target_name, t.host as target_host "
            "FROM scans s LEFT JOIN targets t ON s.target_id = t.id "
            "ORDER BY s.started_at DESC LIMIT 10"
        )
        recent_scans = [dict(r) for r in await cur.fetchall()]

        # Recent pipelines (last 5)
        cur = await db.execute(
            "SELECT p.id, p.mode, p.status, p.started_at, p.finished_at, p.progress, "
            "t.name as target_name, t.host as target_host "
            "FROM pipelines p LEFT JOIN targets t ON p.target_id = t.id "
            "ORDER BY p.started_at DESC LIMIT 5"
        )
        recent_pipelines = [dict(r) for r in await cur.fetchall()]

        # Success rate
        completed = scans_by_status.get("completed", 0)
        failed = scans_by_status.get("failed", 0)
        total_finished = completed + failed
        success_rate = round(completed / total_finished * 100, 1) if total_finished > 0 else 0

        # Proxy status
        proxy = get_proxy_config()

        return {
            "total_targets": total_targets,
            "total_scans": total_scans,
            "total_pipelines": total_pipelines,
            "scans_by_status": scans_by_status,
            "scans_by_tool": scans_by_tool,
            "recent_scans": recent_scans,
            "recent_pipelines": recent_pipelines,
            "success_rate": success_rate,
            "tools_count": len(TOOLS),
            "categories_count": len(CATEGORIES),
            "proxy": {"enabled": proxy.get("enabled", False), "type": proxy.get("type", "none")},
            "uptime_seconds": int(time.time() - START_TIME),
        }
    finally:
        await db.close()


# ── Tools ──────────────────────────────────────────────────────
@app.get("/api/tools")
async def list_tools():
    tools = []
    for tool_id, config in TOOLS.items():
        tool_entry = {
            "id": tool_id,
            "name": config["name"],
            "category": config["category"],
            "description": config["description"],
            "icon": config["icon"],
            "timeout": config["timeout"],
        }
        # Add special tool info if applicable
        if tool_id in SPECIAL_TOOLS:
            tool_entry["special"] = SPECIAL_TOOLS[tool_id]
        tools.append(tool_entry)
    return {"tools": tools, "categories": CATEGORIES}


@app.post("/api/tools/{tool_id}/run")
async def run_single_tool(tool_id: str, body: ToolRun):
    if tool_id not in TOOLS:
        raise HTTPException(404, f"Tool '{tool_id}' not found")

    # For special tools, use direct_input as the target
    effective_target = body.direct_input if body.direct_input and tool_id in SPECIAL_TOOLS else body.target

    # C1: SSRF validation -- this endpoint takes a raw target, bypassing
    # create_target's validation. System tools ignore the target and WiFi
    # tools validate the viewer URL themselves, so only check the rest.
    _no_check = {"network_connections", "process_monitor", "system_info",
                 "ps_security_audit", "wifi_marauder_scan", "m5stick_networks"}
    if tool_id not in SPECIAL_TOOLS and tool_id not in _no_check:
        host_to_check = effective_target
        if "://" in host_to_check:
            from urllib.parse import urlparse
            host_to_check = urlparse(host_to_check).hostname or host_to_check
        valid, reason = validate_target(host_to_check)
        if not valid:
            raise HTTPException(400, f"Invalid target: {reason}")

    result = await run_tool(tool_id, effective_target, **body.params)
    return result


# ── Targets ────────────────────────────────────────────────────
@app.get("/api/targets")
async def list_targets():
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT t.*, COUNT(s.id) as scan_count FROM targets t "
            "LEFT JOIN scans s ON s.target_id = t.id "
            "GROUP BY t.id ORDER BY t.created_at DESC"
        )
        rows = await cursor.fetchall()
        return {"targets": [dict(r) for r in rows]}
    finally:
        await db.close()


@app.post("/api/targets")
async def create_target(body: TargetCreate):
    # SSRF validation
    valid, reason = validate_target(body.host)
    if not valid:
        raise HTTPException(400, f"Invalid target: {reason}")

    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO targets (name, host) VALUES (?, ?)",
            (body.name, body.host)
        )
        await db.commit()
        return {"id": cursor.lastrowid, "name": body.name, "host": body.host}
    finally:
        await db.close()


@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM scans WHERE target_id = ?", (target_id,))
        await db.execute("DELETE FROM pipelines WHERE target_id = ?", (target_id,))
        cur = await db.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        await db.commit()
        if cur.rowcount == 0:  # L4
            raise HTTPException(404, "Target not found")
        return {"deleted": True}
    finally:
        await db.close()


# Consecutive-failure alert (bunker 2.4): N failed scans in a row raise an
# ERROR log line. No external alert channel is configured (webhooks are the
# user's own); the log line is the hookpoint.
_FAIL_STREAK_THRESHOLD = int(os.environ.get("SEC_ALERT_CONSECUTIVE_FAILURES", "5"))
_fail_streak = {"n": 0}


def _bump_failure_streak(status: str) -> None:
    if status == "failed":
        _fail_streak["n"] += 1
        if _fail_streak["n"] >= _FAIL_STREAK_THRESHOLD:
            _log.error(
                "ALERT %d consecutive failed scans (threshold %d); check tools/network",
                _fail_streak["n"], _FAIL_STREAK_THRESHOLD,
            )
    else:
        _fail_streak["n"] = 0


# ── Scans ──────────────────────────────────────────────────────
@app.get("/api/scans")
async def list_scans(target_id: int = None, page: int = 1, per_page: int = 50):
    """List scans, server-side paginated (page/per_page, 1-based).

    Response carries total/page/per_page so clients can render honest
    counts and Prev/Next without refetching. per_page capped at 200.
    """
    db = await get_db()
    try:
        page = max(1, page)
        per_page = min(max(1, per_page), 200)
        offset = (page - 1) * per_page
        clauses: list[str] = []
        params: list[int] = []
        if target_id:
            clauses.append("s.target_id = ?")
            params.append(target_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        base = f"FROM scans s LEFT JOIN targets t ON s.target_id = t.id{where}"
        cur_count = await db.execute(f"SELECT COUNT(*) {base}", params)
        total = (await cur_count.fetchone())[0]
        cursor = await db.execute(
            "SELECT s.*, t.name as target_name, t.host as target_host "
            + base
            + " ORDER BY s.started_at DESC LIMIT ? OFFSET ?",
            [*params, per_page, offset],
        )
        rows = await cursor.fetchall()
        return {"scans": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}
    finally:
        await db.close()


async def _persist_scan_result(scan_id: int, status: str, result: dict):
    """Persist a finished scan's result plus normalized findings and score (Fase 0.4)."""
    db = await get_db()
    try:
        findings_json = json.dumps(result.get("findings", []))
        try:
            score = int(result.get("score") or 0)
        except (TypeError, ValueError):
            score = 0
        await db.execute(
            "UPDATE scans SET status = ?, result = ?, findings = ?, score = ?, finished_at = ? WHERE id = ?",
            (status, json.dumps(result), findings_json, score,
             datetime.utcnow().isoformat(), scan_id)
        )
        await db.commit()
    finally:
        await db.close()


async def _persist_pipeline_result(pipeline_id: int, status: str, result: dict):
    """Persist a finished pipeline's result plus aggregated findings and score (Fase 0.4)."""
    db = await get_db()
    try:
        findings_json = json.dumps(result.get("findings", []))
        try:
            score = int(result.get("score") or 0)
        except (TypeError, ValueError):
            score = 0
        await db.execute(
            "UPDATE pipelines SET status = ?, result = ?, findings = ?, score = ?, progress = 100, finished_at = ? WHERE id = ?",
            (status, json.dumps(result), findings_json, score,
             datetime.utcnow().isoformat(), pipeline_id)
        )
        await db.commit()
    finally:
        await db.close()


@app.post("/api/scans")
async def create_scan(body: ScanCreate, request: Request):
    if body.tool not in TOOLS:
        raise HTTPException(404, f"Tool '{body.tool}' not found")

    is_special = body.tool in SPECIAL_TOOLS

    # For special tools, target_id is optional
    if not is_special and not body.target_id:
        raise HTTPException(400, "target_id is required for non-special tools")

    target_host = ""
    target_name = ""

    if body.target_id:
        db = await get_db()
        try:
            cursor = await db.execute("SELECT * FROM targets WHERE id = ?", (body.target_id,))
            target = await cursor.fetchone()
            if not target:
                raise HTTPException(404, "Target not found")
            target_host = target["host"]
            target_name = target["name"]
        finally:
            await db.close()
    elif is_special:
        target_host = body.direct_input or "direct_input"
        target_name = SPECIAL_TOOLS[body.tool].get("input_label", "direct") or "direct"

    # Create scan record
    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO scans (target_id, tool, status, started_at) VALUES (?, ?, 'running', ?)",
            (body.target_id if body.target_id else None, body.tool, datetime.utcnow().isoformat())
        )
        scan_id = cursor.lastrowid
        await db.commit()
    finally:
        await db.close()

    # Audit log (bunker 2.4): who started what, key truncated.
    _log.info(
        "audit scan created scan_id=%d tool=%s target=%s key=%s ip=%s",
        scan_id, body.tool, target_host or "(none)",
        truncate_key(request.headers.get("X-API-Key")),
        request.client.host if request.client else "?",
    )

    # Run tool in background task so we can track/cancel it
    await broadcast({"type": "scan_start", "scan_id": scan_id, "tool": body.tool})

    # Determine effective target
    if is_special:
        effective_target = body.direct_input or target_host
    else:
        effective_target = target_host

    # M4: never persist audited passwords (DB, webhooks, Splunk)
    _redact = body.tool == "password_audit"
    notified_target = "(redacted)" if _redact else effective_target

    async def _run_scan():
        _log.info("scan started scan_id=%d tool=%s target=%s", scan_id, body.tool, effective_target)
        try:
            result = await run_tool(body.tool, effective_target, **body.params)
            status = "completed" if result.get("success") else "failed"
            stored = dict(result)
            if _redact:
                # M4: never persist audited passwords (DB, webhooks, Splunk)
                stored["target"] = "(redacted)"
                for f in stored.get("findings", []):
                    f["target"] = "(redacted)"
            await _persist_scan_result(scan_id, status, stored)
            _bump_failure_streak(status)
            _log.info(
                "scan finished scan_id=%d tool=%s status=%s elapsed=%.2fs score=%s findings=%d",
                scan_id, body.tool, status,
                result.get("elapsed_seconds", 0),
                result.get("score", 0), len(result.get("findings", [])),
            )

            await broadcast({"type": "scan_complete", "scan_id": scan_id, "status": status, "tool": body.tool})
            # Webhook notification
            await webhooks.notify("scan_complete", {
                "scan_id": scan_id,
                "tool": body.tool,
                "target": notified_target,
                "status": status,
                "elapsed_seconds": result.get("elapsed_seconds", 0),
            })
            # Splunk auto-index (metadata)
            await splunk.index_scan_event(
                scan_id, body.tool, notified_target, status,
                result.get("elapsed_seconds", 0), result.get("success", False)
            )
            # Splunk full results export for rich JSON tools
            if result.get("success") and body.tool in splunk.RICH_JSON_TOOLS:
                tool_result = result.get("result", {})
                if body.tool == "ps_security_audit":
                    # Send one event per audit module (granular Splunk search)
                    audit_results = tool_result.get("results", {})
                    audit_folder = tool_result.get("output_folder", "")
                    if audit_results:
                        await splunk.index_audit_modules(
                            scan_id, body.tool, audit_results, audit_folder
                        )
                else:
                    # WiFi tools: send full JSON as single event
                    await splunk.index_full_results(body.tool, tool_result)
            return {"scan_id": scan_id, "status": status, "result": result}
        except asyncio.CancelledError:
            _log.info("scan cancelled scan_id=%d tool=%s", scan_id, body.tool)
            db2 = await get_db()
            try:
                await db2.execute(
                    "UPDATE scans SET status = 'cancelled', finished_at = ? WHERE id = ?",
                    (datetime.utcnow().isoformat(), scan_id)
                )
                await db2.commit()
            finally:
                await db2.close()
            await broadcast({"type": "scan_complete", "scan_id": scan_id, "status": "cancelled", "tool": body.tool})
            raise
        except Exception as e:
            # M1: full traceback server-side only, client gets a clean error.
            _log.exception("scan failed scan_id=%d tool=%s target=%s", scan_id, body.tool, effective_target)
            db2 = await get_db()
            try:
                await db2.execute(
                    "UPDATE scans SET status = 'failed', result = ?, finished_at = ? WHERE id = ?",
                    (json.dumps({"error": str(e), "success": False}), datetime.utcnow().isoformat(), scan_id)
                )
                await db2.commit()
            finally:
                await db2.close()
            await broadcast({"type": "scan_complete", "scan_id": scan_id, "status": "failed", "tool": body.tool})
            return {"scan_id": scan_id, "status": "failed", "error": str(e)}
        finally:
            _running_scans.pop(scan_id, None)

    task = asyncio.create_task(_run_scan())
    _running_scans[scan_id] = task

    if not body.wait:
        # Non-blocking: client polls GET /api/scans/{id} or listens on the WebSocket
        return {"scan_id": scan_id, "status": "running"}

    # Wait for it to complete (blocking endpoint -- returns when done)
    return await task


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT s.*, t.name as target_name, t.host as target_host "
            "FROM scans s LEFT JOIN targets t ON s.target_id = t.id WHERE s.id = ?",
            (scan_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Scan not found")
        return dict(row)
    finally:
        await db.close()


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int):
    db = await get_db()
    try:
        cur = await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()
        if cur.rowcount == 0:  # L4
            raise HTTPException(404, "Scan not found")
        return {"deleted": True}
    finally:
        await db.close()


@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: int):
    """Cancel a running scan."""
    task = _running_scans.get(scan_id)
    if not task:
        return {"error": "Scan not running or not found"}
    task.cancel()
    return {"cancelled": True, "scan_id": scan_id}


# ── Pipelines ──────────────────────────────────────────────────
@app.get("/api/pipelines")
async def list_pipelines():
    return {"pipelines": PIPELINES}


@app.get("/api/pipelines/history")
async def pipeline_history(mode: str | None = None, status: str | None = None,
                           q: str | None = None, page: int = 1, per_page: int = 20):
    """Pipeline history with optional filters (3E sub-micro-paso 3), paginated.

    mode/status are exact matches; q is a case-insensitive LIKE over mode +
    target name + target host. No params = previous behavior. page/per_page
    are 1-based; per_page capped at 200, default 20 (previous hard cap).
    total/page/per_page in the response mirror the filters.
    """
    db = await get_db()
    try:
        page = max(1, page)
        per_page = min(max(1, per_page), 200)
        offset = (page - 1) * per_page
        clauses: list[str] = []
        params: list[str] = []
        if mode:
            clauses.append("p.mode = ?")
            params.append(mode)
        if status:
            clauses.append("p.status = ?")
            params.append(status)
        if q:
            like = f"%{q}%"
            clauses.append("(p.mode LIKE ? OR t.name LIKE ? OR t.host LIKE ?)")
            params.extend([like] * 3)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        base = ("FROM pipelines p LEFT JOIN targets t ON p.target_id = t.id" + where)
        cur_count = await db.execute(f"SELECT COUNT(*) {base}", params)
        total = (await cur_count.fetchone())[0]
        cursor = await db.execute(
            "SELECT p.*, t.name as target_name, t.host as target_host "
            + base
            + " ORDER BY p.started_at DESC LIMIT ? OFFSET ?",
            [*params, per_page, offset],
        )
        rows = await cursor.fetchall()
        return {"pipelines": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}
    finally:
        await db.close()


@app.get("/api/pipelines/compare")
async def compare_pipelines(target_id: int):
    """Historical comparison (Phase 2): all runs of one target, oldest first.

    Returns each run with parsed findings_count and score so the frontend can
    render the evolution table + sparkline without storing raw JSON clientside.
    Each run also carries the per-finding delta vs the previous run (N-1):
    new / fixed / persistent matched by finding_id (stable since the
    deterministic id in findings.py). First run: empty lists. Legacy rows
    with NULL or corrupted findings are treated as an empty set.
    """
    db = await get_db()
    try:
        cur = await db.execute("SELECT id, name, host FROM targets WHERE id = ?", (target_id,))
        target_row = await cur.fetchone()
        if not target_row:
            raise HTTPException(404, "Target not found")
        cursor = await db.execute(
            "SELECT id, mode, score, findings, started_at, finished_at "
            "FROM pipelines WHERE target_id = ? ORDER BY started_at ASC",
            (target_id,)
        )
        rows = [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()

    runs = []
    prev_items: list[dict] = []
    first_run = True
    for row in rows:
        try:
            parsed = json.loads(row["findings"] or "[]")
            if not isinstance(parsed, list):
                parsed = []
        except (TypeError, json.JSONDecodeError):
            parsed = []
        findings_count = len(parsed)
        # Identity per finding: id + display fields only (no full evidence).
        items = [
            {
                "finding_id": str(f.get("finding_id", "")),
                "severity": f.get("severity", ""),
                "title": f.get("title", ""),
            }
            for f in parsed if isinstance(f, dict) and f.get("finding_id")
        ]
        # First run has no previous run to compare against: empty lists.
        if first_run:
            delta = {"new": [], "fixed": [], "persistent": []}
            first_run = False
        else:
            prev_ids = {it["finding_id"] for it in prev_items}
            cur_ids = {it["finding_id"] for it in items}
            delta = {
                "new": [it for it in items if it["finding_id"] not in prev_ids],
                "fixed": [it for it in prev_items if it["finding_id"] not in cur_ids],
                "persistent": [it for it in items if it["finding_id"] in prev_ids],
            }
        score = row["score"]
        if score is not None:
            try:
                score = int(score)
            except (TypeError, ValueError):
                score = None
        runs.append({
            "id": row["id"],
            "mode": row["mode"],
            "score": score,
            "findings_count": findings_count,
            "new": delta["new"],
            "fixed": delta["fixed"],
            "persistent": delta["persistent"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
        })
        prev_items = items
    return {
        "target_id": target_id,
        "target_name": target_row["name"],
        "target_host": target_row["host"],
        "runs": runs,
    }


@app.post("/api/pipelines")
async def create_pipeline(body: PipelineCreate, request: Request):
    if body.mode not in PIPELINES:
        raise HTTPException(400, f"Invalid mode. Use: {list(PIPELINES.keys())}")

    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM targets WHERE id = ?", (body.target_id,))
        target = await cursor.fetchone()
        if not target:
            raise HTTPException(404, "Target not found")

        cursor = await db.execute(
            "INSERT INTO pipelines (target_id, mode, status, started_at) VALUES (?, ?, 'running', ?)",
            (body.target_id, body.mode, datetime.utcnow().isoformat())
        )
        pipeline_id = cursor.lastrowid
        await db.commit()

        # Audit log (bunker 2.4): who started what, key truncated.
        _log.info(
            "audit pipeline created pipeline_id=%d mode=%s target=%s key=%s ip=%s",
            pipeline_id, body.mode, target["host"],
            truncate_key(request.headers.get("X-API-Key")),
            request.client.host if request.client else "?",
        )

        # Run pipeline in background
        runner = PipelineRunner(
            pipeline_id=pipeline_id,
            mode=body.mode,
            target=target["host"],
            on_progress=broadcast,
        )

        async def run_and_save():
            _log.info(
                "pipeline started pipeline_id=%d mode=%s target=%s",
                pipeline_id, body.mode, target["host"],
            )
            try:
                result = await runner.run()
                status = "completed" if result.get("status") == "completed" else "failed"
                await _persist_pipeline_result(pipeline_id, status, result)
                _log.info(
                    "pipeline finished pipeline_id=%d mode=%s status=%s elapsed=%.2fs score=%s tools=%s",
                    pipeline_id, body.mode, status,
                    result.get("elapsed_seconds", 0),
                    result.get("score", 0), result.get("total_tools", 0),
                )
                # Webhook notification
                await webhooks.notify("pipeline_complete", {
                    "pipeline_id": pipeline_id,
                    "mode": body.mode,
                    "target": target["host"],
                    "status": result.get("status", "completed"),
                    "elapsed_seconds": result.get("elapsed_seconds", 0),
                    "total_tools": result.get("total_tools", 0),
                })
                # Splunk auto-index
                await splunk.index_pipeline_event(
                    pipeline_id, body.mode, target["host"],
                    result.get("status", "completed"),
                    result.get("elapsed_seconds", 0),
                    result.get("total_tools", 0)
                )
            except asyncio.CancelledError:
                _log.info("pipeline cancelled pipeline_id=%d mode=%s", pipeline_id, body.mode)
                try:
                    db2 = await get_db()
                    await db2.execute(
                        "UPDATE pipelines SET status = 'cancelled', finished_at = ? WHERE id = ?",
                        (datetime.utcnow().isoformat(), pipeline_id)
                    )
                    await db2.commit()
                    await db2.close()
                except Exception:
                    pass
                await broadcast({"type": "pipeline_complete", "pipeline_id": pipeline_id, "status": "cancelled"})
                raise
            except Exception as e:
                # Mark as failed if anything goes wrong; M1: traceback server-side only.
                _log.exception("pipeline failed pipeline_id=%d mode=%s target=%s", pipeline_id, body.mode, target["host"])
                try:
                    db2 = await get_db()
                    await db2.execute(
                        "UPDATE pipelines SET status = 'failed', result = ?, finished_at = ? WHERE id = ?",
                        (json.dumps({"error": str(e)}), datetime.utcnow().isoformat(), pipeline_id)
                    )
                    await db2.commit()
                    await db2.close()
                except Exception:
                    pass
            finally:
                _running_pipelines.pop(pipeline_id, None)

        task = asyncio.create_task(run_and_save())
        _running_pipelines[pipeline_id] = task
        return {"pipeline_id": pipeline_id, "mode": body.mode, "status": "started"}
    finally:
        await db.close()


@app.get("/api/pipelines/{pipeline_id}/result")
async def pipeline_result(pipeline_id: int):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM pipelines WHERE id = ?", (pipeline_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Pipeline not found")
        result = dict(row)
        if result.get("result"):
            result["result"] = json.loads(result["result"])
        return result
    finally:
        await db.close()


@app.delete("/api/pipelines/{pipeline_id}")
async def delete_pipeline(pipeline_id: int):
    db = await get_db()
    try:
        cur = await db.execute("DELETE FROM pipelines WHERE id = ?", (pipeline_id,))
        await db.commit()
        if cur.rowcount == 0:  # L4
            raise HTTPException(404, "Pipeline not found")
        return {"deleted": True}
    finally:
        await db.close()


@app.post("/api/pipelines/{pipeline_id}/cancel")
async def cancel_pipeline(pipeline_id: int):
    """Cancel a running pipeline."""
    task = _running_pipelines.get(pipeline_id)
    if not task:
        return {"error": "Pipeline not running or not found"}
    task.cancel()
    return {"cancelled": True, "pipeline_id": pipeline_id}


# ── Webhooks ───────────────────────────────────────────────────
class WebhookCreate(BaseModel):
    name: str
    url: str
    type: str = "generic"  # generic, discord, slack
    events: list[str] = ["scan_complete", "pipeline_complete"]
    enabled: bool = True


def _validate_webhook_url(url: str):
    """Reject webhook URLs that could be used for blind SSRF."""
    from urllib.parse import urlparse
    if not url or not url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail=f"Invalid URL scheme '{parsed.scheme}' -- only http/https allowed")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid URL -- no hostname")
    if is_remote_mode():
        ok, reason = validate_target(parsed.hostname)
        if not ok:
            raise HTTPException(status_code=400, detail=f"Webhook URL blocked: {reason}")
    return url.strip()


@app.get("/api/webhooks")
async def list_webhooks_endpoint():
    return {"webhooks": await webhooks.list_webhooks()}


@app.post("/api/webhooks")
async def create_webhook_endpoint(body: WebhookCreate):
    url = _validate_webhook_url(body.url)
    return await webhooks.create_webhook(body.name, url, body.type, body.events, body.enabled)


@app.put("/api/webhooks/{webhook_id}")
async def update_webhook_endpoint(webhook_id: int, body: WebhookCreate):
    url = _validate_webhook_url(body.url)
    return await webhooks.update_webhook(webhook_id, name=body.name, url=url,
                                         type=body.type, events=body.events, enabled=body.enabled)


@app.delete("/api/webhooks/{webhook_id}")
async def delete_webhook_endpoint(webhook_id: int):
    return await webhooks.delete_webhook(webhook_id)


@app.post("/api/webhooks/{webhook_id}/test")
async def test_webhook_endpoint(webhook_id: int):
    return await webhooks.test_webhook(webhook_id)


# ── Splunk Integration ─────────────────────────────────────────
class SplunkConfig(BaseModel):
    enabled: bool = False
    url: str = "https://127.0.0.1:8089"
    username: str = ""
    password: str = ""
    index: str = "sec_dashboard"
    sourcetype: str = "_json"
    verify_ssl: bool = False


@app.get("/api/splunk")
async def get_splunk():
    config = splunk.get_splunk_config()
    # Don't return password
    config["password"] = "***" if config.get("password") else ""
    return {"config": config}


@app.post("/api/splunk")
async def update_splunk(body: SplunkConfig):
    config = body.dict()
    # Don't overwrite password if masked
    if config.get("password") == "***":
        config["password"] = splunk.get_splunk_config().get("password", "")
    splunk.set_splunk_config(config)
    return {"status": "updated", "enabled": config["enabled"]}


@app.post("/api/splunk/test")
async def test_splunk():
    return await splunk.test_splunk_connection()


@app.post("/api/splunk/export-all")
async def splunk_export_all():
    """Bulk export all scan/pipeline history to Splunk."""
    return await splunk.bulk_export_to_splunk()


# ── Reset ──────────────────────────────────────────────────────
@app.delete("/api/reset")
async def reset_all(confirm: bool = Query(False)):
    """Reset all data. Requires ?confirm=true to prevent accidental wipes."""
    if not confirm:
        raise HTTPException(400, "Confirmation required: add ?confirm=true to reset all data")
    db = await get_db()
    try:
        await db.execute("DELETE FROM scans")
        await db.execute("DELETE FROM pipelines")
        await db.execute("DELETE FROM targets")
        await db.execute("DELETE FROM webhooks")
        await db.commit()
        return {"reset": True}
    finally:
        await db.close()


# ── WebSocket ──────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    # C2: when API key auth is enabled, require ?key= on the WS handshake
    # (unless the handshake already passed Cloudflare Access SSO)
    if API_KEY and not _passed_cloudflare_access(ws) and ws.query_params.get("key") != API_KEY:
        await ws.close(code=4401)
        return
    await ws.accept()
    ws_clients.add(ws)
    try:
        while True:
            data = await ws.receive_text()
            # Echo or handle commands
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws.send_json({"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_clients.discard(ws)


# ── Serve Frontend ────────────────────────────────────────────
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    content = index_file.read_text(encoding="utf-8")
    return HTMLResponse(
        content=content,
        headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"},
    )
