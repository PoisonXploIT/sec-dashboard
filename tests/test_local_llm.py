"""Fase J5a: local LLM explainer over Jev verdicts (reference layer).

No network: _chat is monkeypatched. Covers config rules (loopback-only,
disabled without url+model), bounded JSON parsing and the fail-safe rule
(any failure -> unavailable, never raises).
"""
import asyncio

import pytest

from backend import local_llm


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_config(monkeypatch):
    monkeypatch.setattr(local_llm, "_local_llm_config", {
        "enabled": False, "base_url": "", "model": "", "timeout": 60,
    })
    yield


# ── loopback rule ───────────────────────────────────────────────

@pytest.mark.parametrize("url,ok", [
    ("http://127.0.0.1:8080", True),
    ("http://127.0.0.1:9999/v1", True),
    ("https://localhost:8443", True),
    ("http://[::1]:8080", True),
    ("http://192.168.1.5:8080", False),
    ("http://api.example.com:8080", False),
    ("file:///etc/passwd", False),
    ("", False),
])
def test_is_loopback_url(url, ok):
    assert local_llm.is_loopback_url(url) is ok


# ── config / activation ─────────────────────────────────────────

def test_explain_disabled_by_default():
    res = _run(local_llm.explain_finding({"title": "x"}, {"verdict": "noise"}))
    assert res == {"status": "unavailable", "reason": "disabled"}


def test_explain_enabled_but_not_configured():
    local_llm.set_local_llm_config({"enabled": True, "base_url": "http://127.0.0.1:8080"})
    res = _run(local_llm.explain_finding({}, {}))
    assert res["status"] == "unavailable"
    assert res["reason"] == "not_configured"


# ── explanation parsing (bounded JSON) ──────────────────────────

def _ok_chat(content: str):
    def fake(_messages, _max_tokens):
        return asyncio.sleep(0, result=(200, {
            "model": "local-model",
            "choices": [{"message": {"content": content}}],
        }))
    return fake


def test_explain_ok_parses_bounded_json(monkeypatch):
    local_llm.set_local_llm_config({
        "enabled": True, "base_url": "http://127.0.0.1:8080", "model": "m",
    })
    content = ('prefix noise {"resumen": "r", "porque": "p", '
               '"sugerencia": "' + "x" * 500 + '"} suffix')
    monkeypatch.setattr(local_llm, "_chat", _ok_chat(content))
    res = _run(local_llm.explain_finding({"title": "t"}, {"verdict": "noise"}))
    assert res["status"] == "ok"
    assert res["model"] == "local-model"
    assert res["explanation"]["resumen"] == "r"
    assert res["explanation"]["porque"] == "p"
    # Bounded output: never longer than MAX_EXPLANATION_FIELD.
    assert len(res["explanation"]["sugerencia"]) == local_llm.MAX_EXPLANATION_FIELD


def test_explain_empty_content_degrades(monkeypatch):
    local_llm.set_local_llm_config({
        "enabled": True, "base_url": "http://127.0.0.1:8080", "model": "m",
    })
    monkeypatch.setattr(local_llm, "_chat", _ok_chat(""))
    res = _run(local_llm.explain_finding({}, {}))
    assert res == {"status": "unavailable", "reason": "empty_output"}


def test_explain_unparseable_output_degrades(monkeypatch):
    local_llm.set_local_llm_config({
        "enabled": True, "base_url": "http://127.0.0.1:8080", "model": "m",
    })
    monkeypatch.setattr(local_llm, "_chat", _ok_chat("not json at all"))
    res = _run(local_llm.explain_finding({}, {}))
    assert res == {"status": "unavailable", "reason": "unparseable_output"}


def test_explain_missing_key_degrades(monkeypatch):
    local_llm.set_local_llm_config({
        "enabled": True, "base_url": "http://127.0.0.1:8080", "model": "m",
    })
    content = '{"resumen": "r", "porque": "p"}'  # sugerencia missing
    monkeypatch.setattr(local_llm, "_chat", _ok_chat(content))
    res = _run(local_llm.explain_finding({}, {}))
    assert res["status"] == "unavailable"


def test_explain_network_error_never_raises(monkeypatch):
    local_llm.set_local_llm_config({
        "enabled": True, "base_url": "http://127.0.0.1:8080", "model": "m",
    })

    async def boom(_messages, _max_tokens):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(local_llm, "_chat", boom)
    res = _run(local_llm.explain_finding({}, {}))
    assert res["status"] == "unavailable"
    assert "connection refused" in res["reason"]


def test_explain_bad_http_status_degrades(monkeypatch):
    local_llm.set_local_llm_config({
        "enabled": True, "base_url": "http://127.0.0.1:8080", "model": "m",
    })

    async def server_error(_messages, _max_tokens):
        return 500, {}

    monkeypatch.setattr(local_llm, "_chat", server_error)
    res = _run(local_llm.explain_finding({}, {}))
    assert res == {"status": "unavailable", "reason": "http_500"}


# ── endpoints (backend.main) ────────────────────────────────────

def test_endpoint_rejects_non_loopback_base_url():
    import backend.main as main
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _run(main.update_local_llm(main.LocalLlmConfig(
            enabled=True, base_url="http://192.168.1.5:8080", model="m")))
    assert exc.value.status_code == 400


def test_endpoint_accepts_loopback_and_explains_degraded(monkeypatch):
    import backend.main as main

    async def boom(_messages, _max_tokens):
        raise ConnectionError("no server in tests")

    monkeypatch.setattr(local_llm, "_chat", boom)
    _run(main.update_local_llm(main.LocalLlmConfig(
        enabled=True, base_url="http://127.0.0.1:8080", model="m")))
    res = _run(main.get_local_llm())
    assert res["config"]["enabled"] is True
    assert res["config"]["base_url"] == "http://127.0.0.1:8080"
    # No local server in tests: explain degrades, never raises.
    out = _run(main.explain_finding_endpoint(main.LlmExplainRequest(
        state={"title": "t"}, verdict={"verdict": "noise"})))
    assert out["status"] == "unavailable"
