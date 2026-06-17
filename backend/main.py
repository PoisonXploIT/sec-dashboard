"""FastAPI backend — REST API + WebSocket for real-time updates."""
import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.config import TOOLS, CATEGORIES, PIPELINES, RESULTS_DIR
from backend.models import init_db, get_db
from backend.scanner import run_tool, run_parallel
from backend.pipeline import PipelineRunner
from backend.proxy import get_proxy_config, set_proxy_config, get_tor_status, get_aiohttp_proxy
from backend.report import (
    generate_scan_json, generate_pipeline_json, generate_all_json,
    generate_scan_pdf, generate_pipeline_pdf,
)

app = FastAPI(title="Sec-Dashboard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8444",
        "http://127.0.0.1:8444",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
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


# ── WebSocket connections ──────────────────────────────────────
ws_clients: set[WebSocket] = set()


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
    target_id: int
    tool: str

class PipelineCreate(BaseModel):
    target_id: int
    mode: str

class ToolRun(BaseModel):
    target: str
    params: dict = {}


# ── Events ────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    await init_db()


# ── Health ─────────────────────────────────────────────────────
@app.get("/api/status")
async def status():
    return {
        "status": "ok",
        "version": "1.0.0",
        "tools_count": len(TOOLS),
        "categories": CATEGORIES,
        "uptime": time.time(),
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
            "FROM scans s JOIN targets t ON s.target_id = t.id "
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
        tools.append({
            "id": tool_id,
            "name": config["name"],
            "category": config["category"],
            "description": config["description"],
            "icon": config["icon"],
            "timeout": config["timeout"],
        })
    return {"tools": tools, "categories": CATEGORIES}


@app.post("/api/tools/{tool_id}/run")
async def run_single_tool(tool_id: str, body: ToolRun):
    if tool_id not in TOOLS:
        raise HTTPException(404, f"Tool '{tool_id}' not found")

    result = await run_tool(tool_id, body.target, **body.params)
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
async def list_scans(target_id: int = None):
    db = await get_db()
    try:
        if target_id:
            cursor = await db.execute(
                "SELECT * FROM scans WHERE target_id = ? ORDER BY started_at DESC",
                (target_id,)
            )
        else:
            cursor = await db.execute(
                "SELECT s.*, t.name as target_name, t.host as target_host "
                "FROM scans s JOIN targets t ON s.target_id = t.id "
                "ORDER BY s.started_at DESC LIMIT 50"
            )
        rows = await cursor.fetchall()
        return {"scans": [dict(r) for r in rows]}
    finally:
        await db.close()


@app.post("/api/scans")
async def create_scan(body: ScanCreate):
    if body.tool not in TOOLS:
        raise HTTPException(404, f"Tool '{body.tool}' not found")

    db = await get_db()
    try:
        # Get target
        cursor = await db.execute("SELECT * FROM targets WHERE id = ?", (body.target_id,))
        target = await cursor.fetchone()
        if not target:
            raise HTTPException(404, "Target not found")

        # Create scan record
        cursor = await db.execute(
            "INSERT INTO scans (target_id, tool, status, started_at) VALUES (?, ?, 'running', ?)",
            (body.target_id, body.tool, datetime.utcnow().isoformat())
        )
        scan_id = cursor.lastrowid
        await db.commit()

        # Run tool
        await broadcast({"type": "scan_start", "scan_id": scan_id, "tool": body.tool})
        result = await run_tool(body.tool, target["host"])

        # Update scan record
        status = "completed" if result.get("success") else "failed"
        await db.execute(
            "UPDATE scans SET status = ?, result = ?, finished_at = ? WHERE id = ?",
            (status, json.dumps(result), datetime.utcnow().isoformat(), scan_id)
        )
        await db.commit()

        await broadcast({"type": "scan_complete", "scan_id": scan_id, "status": status})
        return {"scan_id": scan_id, "status": status, "result": result}
    finally:
        await db.close()


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int):
    db = await get_db()
    try:
        await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()
        return {"deleted": True}
    finally:
        await db.close()


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

        asyncio.create_task(run_and_save())
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


# ── Reset ──────────────────────────────────────────────────────
@app.delete("/api/reset")
async def reset_all():
    db = await get_db()
    try:
        await db.execute("DELETE FROM scans")
        await db.execute("DELETE FROM pipelines")
        await db.execute("DELETE FROM targets")
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
