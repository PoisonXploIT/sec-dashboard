"""Splunk integration -- automatic event indexing via REST API."""
import json
import ssl
from datetime import datetime
from typing import Any

import aiohttp

from backend.models import get_db


# Splunk config (stored in memory, set via API)
_splunk_config = {
    "enabled": False,
    "url": "https://127.0.0.1:8089",
    "username": "",
    "password": "",
    "index": "sec_dashboard",
    "sourcetype": "_json",
    "verify_ssl": False,
}


def get_splunk_config() -> dict:
    return dict(_splunk_config)


def set_splunk_config(config: dict):
    global _splunk_config
    _splunk_config.update({k: v for k, v in config.items() if k in _splunk_config})


async def _send_to_splunk(event: dict):
    """Send a single event to Splunk via REST API receivers/simple."""
    if not _splunk_config["enabled"]:
        return

    url = _splunk_config["url"]
    index = _splunk_config["index"]
    sourcetype = _splunk_config["sourcetype"]
    auth = aiohttp.BasicAuth(_splunk_config["username"], _splunk_config["password"])
    verify_ssl = _splunk_config["verify_ssl"]

    # SSL context for self-signed certs
    ssl_ctx = None if verify_ssl else ssl.create_default_context()
    if not verify_ssl and ssl_ctx:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    endpoint = f"{url}/services/receivers/simple?index={index}&sourcetype={sourcetype}"

    try:
        connector = aiohttp.TCPConnector(ssl=ssl_ctx) if ssl_ctx else None
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=connector,
        ) as session:
            async with session.post(
                endpoint,
                data=json.dumps(event, ensure_ascii=False, default=str),
                auth=auth,
                headers={"Content-Type": "application/json"},
            ) as resp:
                if resp.status == 200:
                    return True
                else:
                    print(f"[splunk] HTTP {resp.status}: {await resp.text()[:100]}")
                    return False
    except Exception as e:
        print(f"[splunk] Error: {str(e)[:100]}")
        return False


async def index_scan_event(scan_id: int, tool: str, target: str, status: str,
                           elapsed_seconds: float = 0, success: bool = True):
    """Send a scan completion event to Splunk."""
    event = {
        "event": "sec_dashboard_scan",
        "timestamp": datetime.utcnow().isoformat(),
        "scan_id": scan_id,
        "tool": tool,
        "target": target,
        "status": status,
        "success": success,
        "elapsed_seconds": elapsed_seconds,
    }
    await _send_to_splunk(event)


async def index_pipeline_event(pipeline_id: int, mode: str, target: str,
                               status: str, elapsed_seconds: float = 0,
                               total_tools: int = 0):
    """Send a pipeline completion event to Splunk."""
    event = {
        "event": "sec_dashboard_pipeline",
        "timestamp": datetime.utcnow().isoformat(),
        "pipeline_id": pipeline_id,
        "mode": mode,
        "target": target,
        "status": status,
        "elapsed_seconds": elapsed_seconds,
        "total_tools": total_tools,
    }
    await _send_to_splunk(event)


async def test_splunk_connection() -> dict:
    """Test Splunk connectivity and permissions."""
    if not _splunk_config["enabled"]:
        return {"ok": False, "error": "Splunk integration is disabled"}

    url = _splunk_config["url"]
    auth = aiohttp.BasicAuth(_splunk_config["username"], _splunk_config["password"])
    verify_ssl = _splunk_config["verify_ssl"]

    ssl_ctx = None if verify_ssl else ssl.create_default_context()
    if not verify_ssl and ssl_ctx:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        connector = aiohttp.TCPConnector(ssl=ssl_ctx) if ssl_ctx else None
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=connector,
        ) as session:
            # Check server info
            async with session.get(f"{url}/services/server/info", auth=auth) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    # Extract version
                    import re
                    version_match = re.search(r'version="([^"]+)"', text)
                    version = version_match.group(1) if version_match else "unknown"
                    # Send test event
                    test_event = {
                        "event": "sec_dashboard_test",
                        "timestamp": datetime.utcnow().isoformat(),
                        "message": "Test event from sec-dashboard",
                    }
                    await _send_to_splunk(test_event)
                    return {
                        "ok": True,
                        "version": version,
                        "index": _splunk_config["index"],
                        "message": f"Connected to Splunk {version}. Test event sent to index '{_splunk_config['index']}'.",
                    }
                elif resp.status == 401:
                    return {"ok": False, "error": "Authentication failed -- check username/password"}
                else:
                    return {"ok": False, "error": f"HTTP {resp.status}"}
    except aiohttp.ClientConnectorError as e:
        return {"ok": False, "error": f"Cannot connect to {url}: {str(e)[:100]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:100]}


async def bulk_export_to_splunk() -> dict:
    """Export all scan/pipeline history to Splunk. Useful for initial sync."""
    if not _splunk_config["enabled"]:
        return {"error": "Splunk integration is disabled"}

    db = await get_db()
    try:
        # Get all scans
        cur_s = await db.execute("SELECT s.*, t.name as target_name, t.host as target_host FROM scans s LEFT JOIN targets t ON s.target_id = t.id ORDER BY s.started_at")
        scans = [dict(r) for r in await cur_s.fetchall()]

        # Get all pipelines
        cur_p = await db.execute("SELECT p.*, t.name as target_name, t.host as target_host FROM pipelines p LEFT JOIN targets t ON p.target_id = t.id ORDER BY p.started_at")
        pipelines = [dict(r) for r in await cur_p.fetchall()]
    finally:
        await db.close()

    sent = 0
    failed = 0

    for scan in scans:
        event = {
            "event": "sec_dashboard_scan",
            "timestamp": scan.get("started_at", datetime.utcnow().isoformat()),
            "scan_id": scan.get("id"),
            "tool": scan.get("tool"),
            "status": scan.get("status"),
            "target_name": scan.get("target_name", ""),
            "target_host": scan.get("target_host", ""),
        }
        # Parse result for more details
        if scan.get("result"):
            try:
                result_data = json.loads(scan["result"])
                event["success"] = result_data.get("success")
                event["elapsed_seconds"] = result_data.get("elapsed_seconds")
            except (json.JSONDecodeError, TypeError):
                pass

        ok = await _send_to_splunk(event)
        if ok:
            sent += 1
        else:
            failed += 1

    for pipeline in pipelines:
        event = {
            "event": "sec_dashboard_pipeline",
            "timestamp": pipeline.get("started_at", datetime.utcnow().isoformat()),
            "pipeline_id": pipeline.get("id"),
            "mode": pipeline.get("mode"),
            "status": pipeline.get("status"),
            "target_name": pipeline.get("target_name", ""),
            "target_host": pipeline.get("target_host", ""),
        }
        if pipeline.get("result"):
            try:
                result_data = json.loads(pipeline["result"])
                event["elapsed_seconds"] = result_data.get("elapsed_seconds")
                event["total_tools"] = result_data.get("total_tools")
            except (json.JSONDecodeError, TypeError):
                pass

        ok = await _send_to_splunk(event)
        if ok:
            sent += 1
        else:
            failed += 1

    return {"sent": sent, "failed": failed, "total": sent + failed}