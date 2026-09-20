"""Local LLM explainer for Jev verdicts (Fase J5).

Reference layer only: it never changes a Jev verdict or triage bucket. The
model is a local llama.cpp server (OpenAI-compatible /v1/chat/completions)
that the user starts separately and points at from the UI. There is no
default server and no API key: without both base_url and model configured
(and enabled), this module stays disabled and every call degrades to
"explicacion no disponible".

Rules (approved 2026-09-20, see SEGUIMIENTO.md "J4/J5"):
- base_url is loopback-only (127.0.0.1 / localhost / ::1), any port: the
  explainer must never reach outside the machine.
- Fixed prompt, temperature 0, bounded JSON output {resumen, porque,
  sugerencia}; any failure degrades to unavailable and never breaks a scan.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any
from urllib.parse import urlparse

import aiohttp

_log = logging.getLogger("sec_dashboard.local_llm")

MAX_EXPLANATION_FIELD = 300  # chars per explanation field (bounded output).
# Reasoning models can spend most of the budget thinking before answering;
# 2048 still bounds output (each field is char-capped in _parse_explanation).
_MAX_TOKENS = 2048

SYSTEM_PROMPT = (
    "You are a security analyst assistant. You explain ONE AI verdict produced "
    "by the TypeSafe Jev model about one security finding. The Jev verdict is "
    "official; you only explain it in plain language, you never second-guess "
    "or change it. Respond with ONLY a JSON object (no markdown) with exactly "
    "these keys: resumen (1-2 sentences: what the finding means), porque "
    "(why the model likely gave this verdict and confidence level), sugerencia "
    "(one concrete next step for an operator). Write all three values in "
    "Spanish. Keep each value under 40 words."
)

_local_llm_config: dict[str, Any] = {
    "enabled": False,
    "base_url": os.environ.get("LOCAL_LLM_BASE_URL", ""),
    "model": os.environ.get("LOCAL_LLM_MODEL", ""),
    "timeout": int(os.environ.get("LOCAL_LLM_TIMEOUT", "60")),
}

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def get_local_llm_config() -> dict:
    return dict(_local_llm_config)


def set_local_llm_config(config: dict):
    _local_llm_config.update({k: v for k, v in config.items() if k in _local_llm_config})


def is_loopback_url(url: str) -> bool:
    """True when the URL points at this machine (any port, http or https)."""
    try:
        parsed = urlparse(str(url or ""))
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    return host in _LOOPBACK_HOSTS


def _is_active() -> tuple[bool, str]:
    if not _local_llm_config["enabled"]:
        return False, "disabled"
    if not _local_llm_config.get("base_url") or not _local_llm_config.get("model"):
        return False, "not_configured"
    return True, ""


def _build_user_prompt(state: dict, verdict: dict) -> str:
    payload = {
        "finding": {
            "tool": str(state.get("tool", ""))[:64],
            "category": str(state.get("category", ""))[:64],
            "severity": str(state.get("severity", ""))[:16],
            "title": str(state.get("title", ""))[:200],
            "description": str(state.get("description", ""))[:300],
        },
        "jev_verdict": {
            "verdict": verdict.get("verdict"),
            "confidence": verdict.get("verdict_confidence"),
            "severity_score": verdict.get("severity_score"),
            "immediate_action": verdict.get("immediate_action"),
        },
    }
    return "Explain this Jev verdict. Finding state: " + json.dumps(payload, ensure_ascii=False)


def _parse_explanation(content: str) -> dict | None:
    """Extract the bounded JSON object; None when unparseable."""
    text = (content or "").strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    out = {}
    for key in ("resumen", "porque", "sugerencia"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            return None
        out[key] = value.strip()[:MAX_EXPLANATION_FIELD]
    return out


async def _chat(messages: list[dict], max_tokens: int) -> tuple[int, dict]:
    url = str(_local_llm_config["base_url"]).rstrip("/") + "/v1/chat/completions"
    body = {
        "model": _local_llm_config["model"],
        "messages": messages,
        "temperature": 0,
        "max_tokens": max_tokens,
        # Reasoning models: keep the thinking budget small. Ignored by
        # servers that do not support it.
        "reasoning_effort": "low",
    }
    timeout = aiohttp.ClientTimeout(total=float(_local_llm_config["timeout"]))
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=body) as resp:
            data = await resp.json(content_type=None)
            return resp.status, (data if isinstance(data, dict) else {})


async def explain_finding(state: dict, verdict: dict) -> dict:
    """Explain one stored Jev verdict with the local LLM. Never raises.

    Returns {"status": "ok", "model", "explanation": {...}} or
    {"status": "unavailable", "reason"} (the UI shows 'explicacion no
    disponible' in that case).
    """
    active, reason = _is_active()
    if not active:
        return {"status": "unavailable", "reason": reason}
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _build_user_prompt(state, verdict)},
    ]
    try:
        status, body = await _chat(messages, _MAX_TOKENS)
    except Exception as e:  # server down, timeout, bad JSON... degrade
        _log.warning("local llm explain failed: %s", e)
        return {"status": "unavailable", "reason": str(e)[:200]}
    if status != 200:
        _log.warning("local llm http %s", status)
        return {"status": "unavailable", "reason": f"http_{status}"}
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return {"status": "unavailable", "reason": "bad_response_shape"}
    if not content or not str(content).strip():
        # Typical cause: a reasoning model spent the whole budget thinking.
        return {"status": "unavailable", "reason": "empty_output"}
    explanation = _parse_explanation(content)
    if explanation is None:
        _log.warning("local llm returned non-JSON explanation")
        return {"status": "unavailable", "reason": "unparseable_output"}
    model = body.get("model") or _local_llm_config["model"]
    return {"status": "ok", "model": model, "explanation": explanation}


async def test_local_llm() -> dict:
    """Minimal round-trip against the configured local server. Never raises."""
    active, reason = _is_active()
    if not active:
        return {"status": "unavailable", "reason": reason}
    messages = [{"role": "user", "content": "Reply with the single word: OK"}]
    try:
        status, body = await _chat(messages, 16)
    except Exception as e:
        _log.warning("local llm test failed: %s", e)
        return {"status": "unavailable", "reason": str(e)[:200]}
    if status != 200:
        return {"status": "unavailable", "reason": f"http_{status}"}
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return {"status": "unavailable", "reason": "bad_response_shape"}
    model = body.get("model") or _local_llm_config["model"]
    return {"status": "ok", "model": model, "reply": str(content)[:80]}
