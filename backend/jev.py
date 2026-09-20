"""Jev (TypeSafe) AI enrichment — optional verdict layer over findings.

Fase J (brainstorming: Destino/TYPESAFE AI - JEV/...Brainstorming...).

Security model (see SEGUIMIENTO.md "Fase Jev"):
- Config is in-memory only (same pattern as splunk.py). The API key is never
  written to disk and GET /api/jev returns it masked ("***").
- Env fallback: TYPESAFE_API_KEY pre-fills the key at startup, so a Railway
  deploy can run without ever typing the key into the UI.
- Data minimization: per finding only tool/category/severity/title/description
  (truncated) are sent; evidence dicts are NOT sent. Hard cap max_findings.
- base_url is validated with the same SSRF rules as webhook URLs when it
  differs from the default public endpoint.
- Enrichment is non-blocking: any failure degrades to classic scoring and
  never fails a scan or pipeline. The model id reported by the API is stored
  in results for reproducibility (pinned version).
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import aiohttp

from backend.applog import get_logger

_log = get_logger("jev")

DEFAULT_BASE_URL = "https://api.typesafe.ai/v1/systemone"
PINNED_MODEL = "jev-1.13.0"

# Per-finding state truncation (data minimization, keeps the request small).
_MAX_TITLE = 200
_MAX_DESCRIPTION = 300

_jev_config: dict[str, Any] = {
    "enabled": False,
    "api_key": os.environ.get("TYPESAFE_API_KEY", ""),
    "model": PINNED_MODEL,
    "base_url": DEFAULT_BASE_URL,
    "timeout": 30,
    "max_findings": 100,
}

# ── Questions (constants live here on purpose: one file to audit) ──────────
# English instructions/criteria on purpose (doc: english = best precision).

_VERDICT_CRITERIA = {
    "true_positive": {
        "what": "Real exposure or weakness that an attacker could plausibly exploit",
        "not_for": "Informational items with no exploitable impact",
    },
    "false_positive": {
        "what": "Scanner artifact, misreading of the target, or item that is not actually a problem",
        "not_for": "Real but low-impact findings (those are true_positive)",
    },
    "noise": {
        "what": "Routine informational output with no security relevance (versions, banners, defaults)",
        "not_for": "Anything with a concrete risk or misconfiguration",
    },
}

_SEVERITY_LEVELS = [
    "Informational only; no realistic impact",
    "Real but limited exposure; hardening recommended",
    "Active exposure likely exploitable by an external attacker",
    "Compromise or full takeover plausible from this finding alone",
]


def get_jev_config() -> dict:
    return dict(_jev_config)


def set_jev_config(config: dict):
    _jev_config.update({k: v for k, v in config.items() if k in _jev_config})


def _is_active() -> tuple[bool, str]:
    if not _jev_config["enabled"]:
        return False, "disabled"
    if not _jev_config.get("api_key"):
        return False, "no_api_key"
    return True, ""


def _finding_state(findings: list[dict]) -> list[dict]:
    """Minimal per-finding state (no evidence payloads)."""
    state = []
    for f in findings[: int(_jev_config["max_findings"])]:
        state.append({
            "tool": str(f.get("tool", ""))[:64],
            "category": str(f.get("category", ""))[:64],
            "severity": str(f.get("severity", ""))[:16],
            "title": str(f.get("title", ""))[:_MAX_TITLE],
            "description": str(f.get("description", ""))[:_MAX_DESCRIPTION],
        })
    return state


def _build_questions(n: int) -> dict[str, dict]:
    """One parallel question set per finding (TypeSafe 'Parallel questions')."""
    questions: dict[str, dict] = {}
    for i in range(n):
        base = f"About finding {i} (state[{i}]): "
        questions[f"f{i}_verdict"] = {
            "type": "choice",
            "instructions": base + "which verdict applies to this security finding?",
            "criteria": _VERDICT_CRITERIA,
        }
        questions[f"f{i}_sev"] = {
            "type": "score",
            "instructions": base + "how severe is the risk if left unaddressed?",
            "criteria": _SEVERITY_LEVELS,
        }
        questions[f"f{i}_action"] = {
            "type": "noul",
            "instructions": base + "does this finding require immediate operator action?",
        }
    return questions


def _parse_answers(answers: dict, n: int) -> dict[str, dict]:
    verdicts: dict[str, dict] = {}
    for i in range(n):
        v = answers.get(f"f{i}_verdict") or {}
        s = answers.get(f"f{i}_sev") or {}
        a = answers.get(f"f{i}_action") or {}
        verdicts[str(i)] = {
            "verdict": v.get("choice"),
            "verdict_confidence": v.get("confidence"),
            "severity_score": s.get("score"),
            "immediate_action": a.get("noul"),
        }
    return verdicts


async def _post(payload: dict) -> tuple[int, dict]:
    """POST to the Jev endpoint with one retry on 429/529 (backoff)."""
    url = str(_jev_config["base_url"]).rstrip("/")
    headers = {
        "Authorization": f"Bearer {_jev_config['api_key']}",
        "Content-Type": "application/json",
    }
    timeout = aiohttp.ClientTimeout(total=float(_jev_config["timeout"]))
    for attempt in (1, 2):
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload, headers=headers) as resp:
                body = await resp.json(content_type=None)
                if resp.status in (429, 529) and attempt == 1:
                    retry_after = float(resp.headers.get("Retry-After", "2") or 2)
                    await asyncio.sleep(min(retry_after, 10))
                    continue
                return resp.status, body
    return 0, {}


async def enrich_findings(findings: list[dict]) -> dict:
    """Attach AI verdicts to a findings list. Never raises.

    Returns {"status": "ok"|"skipped"|"error", ...}. Callers store the whole
    dict under result["jev"].
    """
    active, reason = _is_active()
    if not active:
        return {"status": "skipped", "reason": reason}
    if not findings:
        return {"status": "skipped", "reason": "no_findings"}

    state = _finding_state(findings)
    payload = {
        "model": _jev_config["model"],
        "state": state,
        "questions": _build_questions(len(state)),
    }
    try:
        status, body = await _post(payload)
    except Exception as e:  # network, timeout, bad JSON... degrade silently
        _log.warning("jev call failed: %s", e)
        return {"status": "error", "reason": str(e)[:200]}
    if status != 200:
        _log.warning("jev http %s", status)
        return {"status": "error", "reason": f"http_{status}"}

    answers = body.get("answers", {})
    verdicts = _parse_answers(answers, len(state))
    # Map finding index -> stable finding_id when present (UI-friendly join).
    by_id: dict[str, dict] = {}
    for i, f in enumerate(findings[: len(state)]):
        fid = str(f.get("finding_id") or i)
        by_id[fid] = verdicts.get(str(i), {})
    _log.info(
        "jev enrichment ok findings=%d model=%s",
        len(state), body.get("model"),
    )
    return {
        "status": "ok",
        "requested_model": _jev_config["model"],
        "model": body.get("model"),
        "count": len(state),
        "truncated": len(findings) > len(state),
        "usage": body.get("usage"),
        "verdicts": by_id,
    }


async def test_jev() -> dict:
    """Small probe call to validate the API key. Never raises."""
    active, reason = _is_active()
    if not active:
        return {"ok": False, "error": f"not_configured ({reason})"}
    payload = {
        "model": _jev_config["model"],
        "state": "This is a connectivity test from sec-dashboard.",
        "questions": {
            "probe": {
                "type": "noul",
                "instructions": "Is this sentence in English?",
            }
        },
    }
    try:
        status, body = await _post(payload)
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}
    if status != 200:
        return {"ok": False, "error": f"http_{status}"}
    answer = (body.get("answers", {}).get("probe") or {})
    return {
        "ok": True,
        "model": body.get("model"),
        "answer": answer.get("noul"),
        "usage": body.get("usage"),
    }
