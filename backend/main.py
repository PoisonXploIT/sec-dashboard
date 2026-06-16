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

app = FastAPI(title="Sec-Dashboard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    ws_clients -= dead


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
