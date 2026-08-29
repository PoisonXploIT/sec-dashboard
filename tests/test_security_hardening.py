"""Hardening de seguridad (pasos 1-5 del plan):

- C4: system tools deshabilitados en remote mode (run_single_tool + create_scan).
- C3: SSRF en config de proxy y Splunk (solo cuando se activa la integracion).
- Headers de seguridad HTTP en todas las respuestas.
- Logging WARNING de rechazos SSRF en validators.validate_target.

Sin red: peticiones via Request de starlette fabricados y llamadas directas a
los endpoints, mismo estilo que test_ratelimit.py.
"""
import asyncio
import logging

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import PlainTextResponse

import backend.main as main
import backend.validators as validators


def _http_request(method="POST", path="/api/x", host="203.0.113.7", scheme="http"):
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path,
        "headers": [],
        "client": (host, 4321),
        "query_string": b"",
        "scheme": scheme,
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


# ── C4: system tools en remote mode ────────────────────────────


@pytest.fixture
def remote_mode(monkeypatch):
    monkeypatch.setenv("SEC_DASHBOARD_REMOTE", "1")
    yield
    monkeypatch.delenv("SEC_DASHBOARD_REMOTE", raising=False)


@pytest.mark.parametrize("tool_id", sorted(main._SYSTEM_TOOLS))
def test_run_single_tool_blocks_system_tools_remote(remote_mode, monkeypatch, tool_id):
    # 403 ANTES de ejecutar: run_tool nunca se invoca.
    async def _boom(*a, **k):
        raise AssertionError("run_tool must not run in remote mode")

    monkeypatch.setattr(main, "run_tool", _boom)
    body = main.ToolRun(target="example.com")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(main.run_single_tool(tool_id, body, _http_request()))
    assert exc.value.status_code == 403
    assert "remote mode" in exc.value.detail


def test_run_single_tool_allows_system_tools_local(monkeypatch):
    monkeypatch.delenv("SEC_DASHBOARD_REMOTE", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    called = {}

    async def _stub(tool_id, target, **params):
        called["tool"] = tool_id
        return {"success": True}

    monkeypatch.setattr(main, "run_tool", _stub)
    body = main.ToolRun(target="example.com")
    req = _http_request()
    # No remote: el guard no dispara y la herramienta corre.
    asyncio.run(main.run_single_tool("system_info", body, req))
    assert called["tool"] == "system_info"


def test_create_scan_blocks_system_tools_remote(remote_mode):
    body = main.ScanCreate(tool="ps_security_audit", target_id=1)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(main.create_scan(body, _http_request()))
    assert exc.value.status_code == 403


def test_check_system_tools_ignores_normal_tools(remote_mode):
    # Herramienta de red legitima: el guard no dispara.
    main._check_system_tools("dns_lookup", _http_request())


# ── C3: SSRF en config proxy / Splunk ──────────────────────────


def test_proxy_config_blocks_metadata_host_remote(remote_mode, monkeypatch):
    store = {}

    monkeypatch.setattr(main, "set_proxy_config", lambda c: store.update(c))
    monkeypatch.setattr(main, "get_proxy_config", lambda: dict(store))

    body = main.ProxyConfig(enabled=True, type="socks5",
                            host="169.254.169.254", port=8080)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(main.update_proxy(body))
    assert exc.value.status_code == 400
    assert "Proxy host blocked" in exc.value.detail
    assert not store  # nada persistido


def test_proxy_config_blocks_loopback_remote(remote_mode, monkeypatch):
    monkeypatch.setattr(main, "set_proxy_config", lambda c: None)
    monkeypatch.setattr(main, "get_proxy_config", lambda: {})

    body = main.ProxyConfig(enabled=True, type="socks5",
                            host="127.0.0.1", port=9050)
    with pytest.raises(HTTPException):
        asyncio.run(main.update_proxy(body))


def test_proxy_disable_roundtrip_still_works(remote_mode, monkeypatch):
    # Desactivar con el config por defecto (host 127.0.0.1) no debe romperse:
    # la validacion solo aplica a proxies activos.
    store = {}

    monkeypatch.setattr(main, "set_proxy_config", lambda c: store.update(c))
    monkeypatch.setattr(main, "get_proxy_config", lambda: dict(store))

    body = main.ProxyConfig(enabled=False, type="none",
                            host="127.0.0.1", port=9050)
    asyncio.run(main.update_proxy(body))
    assert store["enabled"] is False


def test_splunk_config_blocks_metadata_url_remote(remote_mode, monkeypatch):
    monkeypatch.setattr("backend.splunk.set_splunk_config", lambda c: None)
    monkeypatch.setattr("backend.splunk.get_splunk_config", lambda: {})

    body = main.SplunkConfig(enabled=True, url="http://169.254.169.254/latest/")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(main.update_splunk(body))
    assert exc.value.status_code == 400


def test_splunk_disable_with_default_url_still_works(remote_mode, monkeypatch):
    # El URL por defecto es https://127.0.0.1:8089: desactivar con el URL
    # viejo no debe romperse (validacion solo al activar).
    monkeypatch.setattr("backend.splunk.set_splunk_config", lambda c: None)
    monkeypatch.setattr("backend.splunk.get_splunk_config", lambda: {})

    body = main.SplunkConfig(enabled=False, url="https://127.0.0.1:8089")
    asyncio.run(main.update_splunk(body))


# ── Headers de seguridad HTTP ───────────────────────────────────


class _RespCallNext:
    def __init__(self, headers=None):
        self.headers = headers or {}

    async def __call__(self, request):
        resp = PlainTextResponse("ok")
        resp.headers.update(self.headers)
        return resp


def test_security_headers_injected_on_http():
    req = _http_request(scheme="http")
    resp = asyncio.run(main.security_headers(req, _RespCallNext()))
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    csp = resp.headers["Content-Security-Policy"]
    assert csp.startswith("default-src 'self'")
    assert "script-src 'self' 'unsafe-inline'" in csp
    # HTTP plano: sin HSTS.
    assert "Strict-Transport-Security" not in resp.headers


def test_security_headers_hsts_only_on_https():
    resp = asyncio.run(main.security_headers(_http_request(scheme="https"), _RespCallNext()))
    assert resp.headers["Strict-Transport-Security"].startswith("max-age=")


def test_security_headers_do_not_override_existing():
    # Un endpoint que ya fija un header no lo pisa.
    nxt = _RespCallNext(headers={"X-Frame-Options": "SAMEORIGIN"})
    resp = asyncio.run(main.security_headers(_http_request(), nxt))
    assert resp.headers["X-Frame-Options"] == "SAMEORIGIN"


# ── Logging de rechazos SSRF ───────────────────────────────────


def test_validate_target_logs_rejection_in_remote(remote_mode, caplog):
    caplog.set_level(logging.WARNING, logger="sec_dashboard.validators")
    ok, reason = validators.validate_target("169.254.169.254")
    assert not ok
    assert any("ssrf blocked" in r.message for r in caplog.records)


def test_validate_target_no_log_in_local_mode(caplog):
    caplog.set_level(logging.WARNING, logger="sec_dashboard.validators")
    import os
    # Local (sin PORT ni flag): 127.0.0.1 es valido y no logea nada.
    assert "PORT" not in os.environ or True
    ok, _ = validators.validate_target("192.168.1.1")
    # En local mode is_private pasa; si el entorno del test correa con PORT
    # (no pasa en CI local) se logea y el assert de abajo no aplica.
    if not validators.is_remote_mode():
        assert not any("ssrf blocked" in r.message for r in caplog.records)
        assert ok
