"""Webhook notifications -- Discord, Slack, and generic HTTP webhooks."""
import json
from datetime import datetime
from typing import Any

import aiohttp

from backend.models import get_db


async def _load_webhooks() -> list[dict]:
    """Load enabled webhooks from DB."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM webhooks WHERE enabled = 1")
        rows = [dict(r) for r in await cursor.fetchall()]
        return rows
    finally:
        await db.close()


def _parse_events(webhook: dict) -> set[str]:
    """Parse the events field into a set."""
    try:
        events = json.loads(webhook.get("events", "[]"))
        return set(events)
    except (json.JSONDecodeError, TypeError):
        return {"scan_complete", "pipeline_complete"}


async def notify(event_type: str, data: dict):
    """Send webhook notifications for an event.

    Args:
        event_type: "scan_complete" or "pipeline_complete"
        data: Event payload with tool/mode, target, status, elapsed, etc.
    """
    webhooks = await _load_webhooks()
    if not webhooks:
        return

    for wh in webhooks:
        events = _parse_events(wh)
        if event_type not in events:
            continue

        wh_type = wh.get("type", "generic")
        url = wh.get("url", "")
        if not url:
            continue

        payload = _build_payload(wh_type, event_type, data)

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.post(url, json=payload) as resp:
                    pass  # fire and forget
        except Exception:
            pass  # don't let webhook failures break the app


def _build_payload(wh_type: str, event_type: str, data: dict) -> dict:
    """Build webhook payload based on type."""
    timestamp = datetime.utcnow().isoformat() + "Z"

    if wh_type == "discord":
        # Discord webhook format
        color = 0x3fb950 if data.get("status") == "completed" else 0xf85149
        title = f"Scan Complete" if event_type == "scan_complete" else "Pipeline Complete"
        tool_or_mode = data.get("tool", data.get("mode", "unknown"))
        target = data.get("target", "unknown")
        elapsed = data.get("elapsed_seconds", "?")
        status = data.get("status", "unknown")

        embed = {
            "title": f"Sec-Dashboard: {title}",
            "color": color,
            "fields": [
                {"name": "Target", "value": str(target), "inline": True},
                {"name": "Tool/Mode", "value": str(tool_or_mode), "inline": True},
                {"name": "Status", "value": str(status), "inline": True},
                {"name": "Elapsed", "value": f"{elapsed}s", "inline": True},
            ],
            "footer": {"text": f"sec-dashboard | {timestamp}"},
        }
        return {"embeds": [embed]}

    elif wh_type == "slack":
        # Slack webhook format
        status_emoji = ":white_check_mark:" if data.get("status") == "completed" else ":x:"
        tool_or_mode = data.get("tool", data.get("mode", "unknown"))
        target = data.get("target", "unknown")
        elapsed = data.get("elapsed_seconds", "?")

        text = f"*Sec-Dashboard* {status_emoji} {event_type.replace('_', ' ').title()}\n"
        text += f"Target: `{target}` | Tool: `{tool_or_mode}` | Elapsed: `{elapsed}s`"

        return {"text": text}

    else:
        # Generic JSON webhook
        return {
            "source": "sec-dashboard",
            "event": event_type,
            "timestamp": timestamp,
            "data": data,
        }


# ── Webhook CRUD (called from main.py) ──────────────────────
async def list_webhooks() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM webhooks ORDER BY created_at DESC")
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def create_webhook(name: str, url: str, wh_type: str = "generic",
                         events: list[str] = None, enabled: bool = True) -> dict:
    db = await get_db()
    try:
        events_json = json.dumps(events or ["scan_complete", "pipeline_complete"])
        cursor = await db.execute(
            "INSERT INTO webhooks (name, url, type, enabled, events) VALUES (?, ?, ?, ?, ?)",
            (name, url, wh_type, 1 if enabled else 0, events_json),
        )
        await db.commit()
        return {"id": cursor.lastrowid, "name": name, "url": url, "type": wh_type, "enabled": enabled}
    finally:
        await db.close()


async def update_webhook(webhook_id: int, **kwargs) -> dict:
    db = await get_db()
    try:
        fields = []
        values = []
        for k, v in kwargs.items():
            if k == "events":
                v = json.dumps(v)
            elif k == "enabled":
                v = 1 if v else 0
            fields.append(f"{k} = ?")
            values.append(v)
        if not fields:
            return {"updated": False, "reason": "no fields"}
        values.append(webhook_id)
        await db.execute(f"UPDATE webhooks SET {', '.join(fields)} WHERE id = ?", values)
        await db.commit()
        return {"updated": True}
    finally:
        await db.close()


async def delete_webhook(webhook_id: int) -> dict:
    db = await get_db()
    try:
        await db.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        await db.commit()
        return {"deleted": True}
    finally:
        await db.close()


async def test_webhook(webhook_id: int) -> dict:
    """Send a test notification to a webhook."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        row = await cursor.fetchone()
        if not row:
            return {"error": "Webhook not found"}
        wh = dict(row)
    finally:
        await db.close()

    wh_type = wh.get("type", "generic")
    url = wh.get("url", "")
    if not url:
        return {"error": "Webhook has no URL"}

    payload = _build_payload(wh_type, "scan_complete", {
        "tool": "test",
        "target": "test.example.com",
        "status": "completed",
        "elapsed_seconds": 0.01,
    })

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.post(url, json=payload) as resp:
                return {"status_code": resp.status, "ok": resp.status < 400}
    except Exception as e:
        return {"error": str(e)[:200]}