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
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import aiohttp

from backend.applog import get_logger

_log = get_logger("jev")

DEFAULT_BASE_URL = "https://api.typesafe.ai/v1/systemone"
PINNED_MODEL = "jev-1.13.0"
# Backend local (LAY\u00c1, laya-serve en 127.0.0.1:8787, CPU). Segunda opcion
# conmutable; cloud (Jev) sigue siendo el default.
DEFAULT_LAYA_BASE_URL = "http://127.0.0.1:8787/v1/systemone"
DEFAULT_LAYA_MODEL = "multilingual"
_LAYA_ENV = Path(r"C:\Users\Sammi\ai-netwatch\data\laya_serve.env")

# Per-finding state truncation (data minimization, keeps the request small).
_MAX_TITLE = 200
_MAX_DESCRIPTION = 300

# LAYA: shared Jev verdict dataset (passive capture, fail-safe).
_LAYA_CASES_PATH = Path(r"C:\Users\Sammi\AI\laya-data\cases_scan.jsonl")

_jev_config: dict[str, Any] = {
    "enabled": False,
    "api_key": os.environ.get("TYPESAFE_API_KEY", ""),
    "model": PINNED_MODEL,
    "base_url": DEFAULT_BASE_URL,
    "timeout": 30,
    "max_findings": 100,
    # cloud | local (local = laya-serve; no requiere api_key de TypeSafe).
    "backend": "cloud",
    "laya_base_url": DEFAULT_LAYA_BASE_URL,
    "laya_model": DEFAULT_LAYA_MODEL,
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
    if str(_jev_config.get("backend") or "cloud") == "local":
        return True, ""  # el serve local no usa api_key de TypeSafe
    if not _jev_config.get("api_key"):
        return False, "no_api_key"
    return True, ""


def _laya_key() -> str:
    """LAYA_API_KEY desde el entorno o data/laya_serve.env (nunca en claro en config)."""
    k = os.environ.get("LAYA_API_KEY")
    if k:
        return k
    try:
        for line in _LAYA_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("LAYA_API_KEY="):
                os.environ["LAYA_API_KEY"] = line.split("=", 1)[1].strip()
                return os.environ["LAYA_API_KEY"]
    except OSError:
        pass
    return "local"


def _local_questions() -> dict:
    """Plantilla UNICA sin indice para /v1/systemone/batch (patron A3)."""
    return {
        "verdict": {
            "type": "choice",
            "instructions": "which verdict applies to this security finding?",
            "criteria": _VERDICT_CRITERIA,
        },
        "sev": {
            "type": "score",
            "instructions": "how severe is the risk if left unaddressed?",
            "criteria": _SEVERITY_LEVELS,
        },
        "action": {
            "type": "noul",
            "instructions": "does this finding require immediate operator action?",
            "criteria": {"false": "no immediate action needed",
                         "true": "yes, requires immediate action now"},
        },
    }


async def _post_local(states: list[dict]) -> tuple[int, dict]:
    """POST /v1/systemone/batch al laya-serve (states[] + plantilla unica)."""
    url = str(_jev_config["laya_base_url"]).rstrip("/") + "/batch"
    headers = {"Authorization": f"Bearer {_laya_key()}",
               "Content-Type": "application/json"}
    payload = {"model": _jev_config["laya_model"], "states": states,
               "questions": _local_questions()}
    total = max(float(_jev_config["timeout"]), 60 + 5 * len(states))
    timeout = aiohttp.ClientTimeout(total=total)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            body = await resp.json(content_type=None)
            return resp.status, body


def _parse_local(results: list, n: int) -> dict[str, dict]:
    verdicts: dict[str, dict] = {}
    for i in range(n):
        r = results[i] if i < len(results) and isinstance(results[i], dict) else {}
        a = r.get("answers") or {}
        cls = a.get("verdict") or {}
        sev = a.get("sev") or {}
        act = a.get("action") or {}
        try:
            immediate = "yes" if float(act.get("noul")) >= 0.5 else "no"
        except (TypeError, ValueError):
            immediate = None
        verdicts[str(i)] = {
            "verdict": cls.get("choice"),
            "verdict_confidence": cls.get("answer_confidence"),
            "severity_score": sev.get("score"),
            "immediate_action": immediate,
        }
    return verdicts


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


def _laya_onehot(labels, chosen) -> dict:
    """One-hot from argmax when Jev does not return probabilities."""
    if not labels or chosen is None:
        return {}
    return {k: (1.0 if k == chosen else 0.0) for k in labels}


def _laya_gold(answers: dict, i: int) -> dict:
    """Gold with FULL probability distributions (soft targets) for finding i."""
    v = answers.get(f"f{i}_verdict") or {}
    s = answers.get(f"f{i}_sev") or {}
    a = answers.get(f"f{i}_action") or {}

    probs = v.get("probabilities")
    if not isinstance(probs, dict) or not probs:
        probs = _laya_onehot(list(_VERDICT_CRITERIA), v.get("choice"))
    gold: dict[str, dict] = {f"f{i}_verdict": {"probabilities": probs}}

    probs = s.get("probabilities")
    if not isinstance(probs, dict) or not probs:
        score = s.get("score")
        keys = [str(k) for k in range(len(_SEVERITY_LEVELS))]
        probs = _laya_onehot(keys, str(score)) if score is not None else {}
    gold[f"f{i}_sev"] = {"probabilities": probs}

    noul = a.get("noul")
    try:
        noul = float(noul)
    except (TypeError, ValueError):
        noul = None
    if noul is not None:
        probs = {"false": round(1.0 - noul, 6), "true": round(noul, 6)}
    else:
        probs = a.get("probabilities")
        if not isinstance(probs, dict) or not probs:
            probs = {}
    gold[f"f{i}_action"] = {"probabilities": probs}
    return gold


_LAYA_VOLATILE = frozenset((
    "ts", "first_seen", "last_seen", "seen_count", "scan_id", "id",
    "created_at", "timestamp", "run_id", "audit_id", "event_id",
))


def _laya_content_sig(state, questions, gold) -> str:
    """Content signature for dedup (stable across re-scans of the same target).

    Ignores volatile state fields and reduces gold to per-question argmax so
    minimum probability variation does not create a new case. Must stay in
    sync with AI/laya-data/merge_dedup.py.
    """
    s = {k: v for k, v in state.items() if k not in _LAYA_VOLATILE} \
        if isinstance(state, dict) else state
    g = {}
    for qid, item in (gold or {}).items():
        probs = item.get("probabilities") if isinstance(item, dict) else None
        if isinstance(probs, dict) and probs:
            g[qid] = max(sorted(probs), key=lambda k: probs[k])
        else:
            g[qid] = None
    q = sorted((questions or {}).items()) if isinstance(questions, dict) else questions
    payload = {"s": s, "q": q, "g": g}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _laya_capture(state: list[dict], questions: dict, answers: dict) -> None:
    """Append one line per finding to the LAYA dataset. Never raises.

    Dedup by content signature (volatile fields + gold argmax), not exact line hash.
    """
    try:
        lines = []
        for i, st in enumerate(state):
            qs = {k: v for k, v in questions.items() if k.startswith(f"f{i}_")}
            lines.append({"state": st, "questions": qs, "gold": _laya_gold(answers, i)})
        sigs = set()
        if _LAYA_CASES_PATH.exists():
            with open(_LAYA_CASES_PATH, encoding="utf-8") as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        obj = json.loads(raw)
                        sigs.add(_laya_content_sig(
                            obj.get("state"), obj.get("questions"), obj.get("gold")))
                    except Exception:
                        pass
        new_lines = []
        for obj in lines:
            sig = _laya_content_sig(obj["state"], obj["questions"], obj["gold"])
            if sig not in sigs:
                sigs.add(sig)
                # CRITICO: sin sort_keys. El orden de `criteria` es posicional;
                # ordenarlo desalinea entrenamiento e inferencia (2026-10-04).
                new_lines.append(json.dumps(obj, ensure_ascii=False))
        if not new_lines:
            return
        _LAYA_CASES_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_LAYA_CASES_PATH, "a", encoding="utf-8") as f:
            for line in new_lines:
                f.write(line + "\n")
    except Exception:
        pass  # passive capture: never breaks the scan


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

    if str(_jev_config.get("backend") or "cloud") == "local":
        try:
            status, body = await _post_local(state)
        except Exception as e:  # noqa: BLE001
            _log.warning("laya local call failed: %s", e)
            return {"status": "error", "reason": str(e)[:200]}
        if status != 200:
            _log.warning("laya local http %s", status)
            return {"status": "error", "reason": f"http_{status}"}
        results = body.get("results") if isinstance(body, dict) else None
        if not isinstance(results, list):
            return {"status": "error", "reason": "bad_batch_shape"}
        verdicts = _parse_local(results, len(state))
        by_id = {}
        for i, f in enumerate(findings[: len(state)]):
            by_id[str(f.get("finding_id") or i)] = verdicts.get(str(i), {})
        _log.info("laya local enrichment ok findings=%d model=%s",
                  len(state), body.get("model"))
        return {"status": "ok", "backend": "local",
                "requested_model": _jev_config["laya_model"],
                "model": body.get("model"), "count": len(state),
                "truncated": len(findings) > len(state),
                "verdicts": verdicts, "by_id": by_id}

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
    _laya_capture(state, payload["questions"], answers)  # LAYA dataset (fail-safe)
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
    if str(_jev_config.get("backend") or "cloud") == "local":
        try:
            status, body = await _post_local(
                [{"title": "selftest", "tool": "sec-dashboard-selftest"}])
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:200]}
        if status != 200:
            return {"ok": False, "error": f"http_{status}"}
        results = body.get("results") or []
        ans = (results[0].get("answers") if results else {}) or {}
        return {"ok": True, "model": body.get("model"),
                "answer": (ans.get("verdict") or {}).get("choice")}
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
