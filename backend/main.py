"""FastAPI backend — REST API + WebSocket for real-time updates."""
import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.config import TOOLS, CATEGORIES, PIPELINES, RESULTS_DIR, SPECIAL_TOOLS
from backend.models import init_db, get_db
from backend.scanner import run_tool, run_parallel
from backend.pipeline import PipelineRunner
from backend.proxy import get_proxy_config, set_proxy_config, get_tor_status, get_aiohttp_proxy
from backend.report import (
    generate_scan_json, generate_pipeline_json, generate_all_json,
    generate_scan_pdf, generate_pipeline_pdf, generate_all_pdf,
)
from backend.validators import validate_target, is_remote_mode
from backend import webhooks
from backend import splunk

app = FastAPI(title="Sec-Dashboard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8444",
        "http://127.0.0.1:8444",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://sec.sammideblas.com",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)




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
    tor = get_tor_status()
    return {"config": config, "tor_status": tor}

@app.post("/api/proxy")
async def update_proxy(body: ProxyConfig):
    set_proxy_config(body.dict())
    return {"status": "updated", "config": get_proxy_config()}

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
            print("[startup] Migrated scans table: target_id is now nullable")
    except Exception as e:
        print(f"[startup] Migration check: {e}")
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
            print(f"[startup] Marked {cur.rowcount} orphaned running scans as failed")
    finally:
        await db.close()


# ── Health ─────────────────────────────────────────────────────
@app.get("/api/status")
async def status():
    return {
        "status": "ok",
        "version": "1.0.0",
        "tools_count": len(TOOLS),
        "categories": CATEGORIES,
        "uptime": time.time(),
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
            "FROM pipelines p JOIN targets t ON p.target_id = t.id "
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
        await db.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        await db.commit()
        return {"deleted": True}
    finally:
        await db.close()


# ── Scans ──────────────────────────────────────────────────────
@app.get("/api/scans")
async def list_scans(target_id: int = None, offset: int = 0, limit: int = 50):
    db = await get_db()
    try:
        limit = min(limit, 200)  # cap at 200
        offset = max(offset, 0)
        if target_id:
            cursor = await db.execute(
                "SELECT * FROM scans WHERE target_id = ? ORDER BY started_at DESC LIMIT ? OFFSET ?",
                (target_id, limit, offset)
            )
        else:
            cursor = await db.execute(
                "SELECT s.*, t.name as target_name, t.host as target_host "
                "FROM scans s LEFT JOIN targets t ON s.target_id = t.id "
                "ORDER BY s.started_at DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
        rows = await cursor.fetchall()
        return {"scans": [dict(r) for r in rows]}
    finally:
        await db.close()


@app.post("/api/scans")
async def create_scan(body: ScanCreate):
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

    # Run tool in background task so we can track/cancel it
    await broadcast({"type": "scan_start", "scan_id": scan_id, "tool": body.tool})

    # Determine effective target
    if is_special:
        effective_target = body.direct_input or target_host
    else:
        effective_target = target_host

    async def _run_scan():
        try:
            result = await run_tool(body.tool, effective_target, **body.params)
            db2 = await get_db()
            try:
                status = "completed" if result.get("success") else "failed"
                await db2.execute(
                    "UPDATE scans SET status = ?, result = ?, finished_at = ? WHERE id = ?",
                    (status, json.dumps(result), datetime.utcnow().isoformat(), scan_id)
                )
                await db2.commit()
            finally:
                await db2.close()

            await broadcast({"type": "scan_complete", "scan_id": scan_id, "status": status, "tool": body.tool})
            # Webhook notification
            await webhooks.notify("scan_complete", {
                "scan_id": scan_id,
                "tool": body.tool,
                "target": effective_target,
                "status": status,
                "elapsed_seconds": result.get("elapsed_seconds", 0),
            })
            # Splunk auto-index (metadata)
            await splunk.index_scan_event(
                scan_id, body.tool, effective_target, status,
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

    # Wait for it to complete (blocking endpoint -- returns when done)
    return await task


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()
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
async def pipeline_history():
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT p.*, t.name as target_name, t.host as target_host "
            "FROM pipelines p JOIN targets t ON p.target_id = t.id "
            "ORDER BY p.started_at DESC LIMIT 20"
        )
        rows = await cursor.fetchall()
        return {"pipelines": [dict(r) for r in rows]}
    finally:
        await db.close()


@app.post("/api/pipelines")
async def create_pipeline(body: PipelineCreate):
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

        # Run pipeline in background
        runner = PipelineRunner(
            pipeline_id=pipeline_id,
            mode=body.mode,
            target=target["host"],
            on_progress=broadcast,
        )

        async def run_and_save():
            try:
                result = await runner.run()
                db2 = await get_db()
                try:
                    status = "completed" if result.get("status") == "completed" else "failed"
                    await db2.execute(
                        "UPDATE pipelines SET status = ?, result = ?, progress = 100, finished_at = ? WHERE id = ?",
                        (status, json.dumps(result), datetime.utcnow().isoformat(), pipeline_id)
                    )
                    await db2.commit()
                finally:
                    await db2.close()
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
                # Mark as failed if anything goes wrong
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
        await db.execute("DELETE FROM pipelines WHERE id = ?", (pipeline_id,))
        await db.commit()
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


@app.get("/api/webhooks")
async def list_webhooks_endpoint():
    return {"webhooks": await webhooks.list_webhooks()}


@app.post("/api/webhooks")
async def create_webhook_endpoint(body: WebhookCreate):
    return await webhooks.create_webhook(body.name, body.url, body.type, body.events, body.enabled)


@app.put("/api/webhooks/{webhook_id}")
async def update_webhook_endpoint(webhook_id: int, body: WebhookCreate):
    return await webhooks.update_webhook(webhook_id, name=body.name, url=body.url,
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
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
