"""Auth hardening (bunker 2.1): key truncation, lockout tracker y cableado.

Sin red ni sleep: el FailedAuthTracker corre contra un reloj manual y los
middlewares se prueban con Request de starlette fabricados llamando a la
funcion del middleware directamente, mismo estilo que test_ratelimit.py.
"""
import asyncio
import json

from starlette.requests import Request

from backend.authguard import FailedAuthTracker, truncate_key


class FrozenClock:
    """Reloj manual: avanza solo cuando el test lo dice."""

    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


# ── truncate_key ───────────────────────────────────────────────


def test_truncate_key_variants():
    assert truncate_key(None) == "(none)"
    assert truncate_key("") == "(none)"
    # Clave corta: solo 2 chars, nunca la plena.
    assert truncate_key("ab12") == "ab..."
    # Clave larga: los primeros 8 y nada mas.
    assert truncate_key("0123456789abcdef") == "01234567..."


# ── FailedAuthTracker (unitario) ────────────────────────────────


def test_lockout_opens_after_n_failures():
    clock = FrozenClock()
    tr = FailedAuthTracker(3, 300.0, 600.0, clock=clock)
    for _ in range(2):
        tr.record_failure("a")
        assert tr.is_blocked("a") == (False, 0)
    tr.record_failure("a")
    blocked, retry = tr.is_blocked("a")
    assert blocked
    assert retry == 600


def test_failures_expire_with_window():
    clock = FrozenClock()
    tr = FailedAuthTracker(3, 300.0, 600.0, clock=clock)
    # Tres fallos separados mas alla de la ventana: no acumulan.
    for t in (0.0, 400.0, 800.0):
        clock.t = t
        tr.record_failure("a")
        assert tr.is_blocked("a") == (False, 0)


def test_lockout_expires():
    clock = FrozenClock()
    tr = FailedAuthTracker(2, 300.0, 60.0, clock=clock)
    tr.record_failure("a")
    tr.record_failure("a")
    assert tr.is_blocked("a")[0]
    clock.advance(61.0)
    assert tr.is_blocked("a") == (False, 0)


def test_success_clears_counters_and_lockout():
    clock = FrozenClock()
    tr = FailedAuthTracker(3, 300.0, 600.0, clock=clock)
    tr.record_failure("a")
    tr.record_failure("a")
    tr.record_success("a")
    # Un exito limpia: los fallos vuelven a contar desde cero.
    for _ in range(2):
        tr.record_failure("a")
        assert tr.is_blocked("a") == (False, 0)
    # Y levanta un ban activo (origen CF compartido: no secuestrar al legitimo).
    for _ in range(3):
        tr.record_failure("b")
    assert tr.is_blocked("b")[0]
    tr.record_success("b")
    assert tr.is_blocked("b") == (False, 0)


def test_peers_are_independent():
    clock = FrozenClock()
    tr = FailedAuthTracker(2, 300.0, 600.0, clock=clock)
    tr.record_failure("a")
    tr.record_failure("a")
    assert tr.is_blocked("a")[0]
    assert tr.is_blocked("b") == (False, 0)


# ── Cableado en main.py ─────────────────────────────────────────


def _http_request(method, path, host="203.0.113.7", key=None):
    headers = []
    if key is not None:
        headers.append((b"x-api-key", key.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path,
        "headers": headers,
        "client": (host, 4321),
        "query_string": b"",
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


class CallNext:
    def __init__(self):
        self.calls = 0

    async def __call__(self, request):
        self.calls += 1
        return "next"


def test_require_api_key_rejects_wrong_or_missing(monkeypatch):
    import backend.main as main

    monkeypatch.setattr(main, "API_KEY", "sekrit-key-1234")
    clock = FrozenClock()
    monkeypatch.setattr(main, "_auth_lockout", FailedAuthTracker(5, 300.0, 600.0, clock=clock))

    nxt = CallNext()
    resp = asyncio.run(main.require_api_key(_http_request("GET", "/api/status", key="wrong"), nxt))
    assert resp.status_code == 401
    assert nxt.calls == 0
    resp = asyncio.run(main.require_api_key(_http_request("GET", "/api/status"), nxt))
    assert resp.status_code == 401

    # Clave correcta: pasa y limpia contadores.
    ok = asyncio.run(main.require_api_key(_http_request("GET", "/api/status", key="sekrit-key-1234"), nxt))
    assert ok == "next"
    assert nxt.calls == 1


def test_require_api_key_lockout_after_n_failures(monkeypatch):
    import backend.main as main

    monkeypatch.setattr(main, "API_KEY", "sekrit-key-1234")
    clock = FrozenClock()
    tracker = FailedAuthTracker(3, 300.0, 600.0, clock=clock)
    monkeypatch.setattr(main, "_auth_lockout", tracker)

    nxt = CallNext()
    for _ in range(3):
        resp = asyncio.run(main.require_api_key(_http_request("GET", "/api/status", key="wrong"), nxt))
        assert resp.status_code == 401
    # Ban abierto: ni siquiera con la clave correcta hay acceso.
    resp = asyncio.run(main.require_api_key(_http_request("GET", "/api/status", key="sekrit-key-1234"), nxt))
    assert resp.status_code == 403
    assert int(resp.headers["retry-after"]) >= 1
    assert json.loads(resp.body)["detail"].startswith("Too many failed auth attempts")
    # Expirado el ban: la clave correcta vuelve a pasar.
    clock.advance(601.0)
    ok = asyncio.run(main.require_api_key(_http_request("GET", "/api/status", key="sekrit-key-1234"), nxt))
    assert ok == "next"


def test_cf_access_bypass_and_options_preflight(monkeypatch):
    import backend.main as main

    monkeypatch.setattr(main, "API_KEY", "sekrit-key-1234")
    clock = FrozenClock()
    monkeypatch.setattr(main, "_auth_lockout", FailedAuthTracker(5, 300.0, 600.0, clock=clock))

    nxt = CallNext()
    # Cf-Access-Authenticated-User-Email inyectado por Cloudflare: sin key.
    scope_extra = {"headers": [(b"cf-access-authenticated-user-email", b"u@example.com")]}
    req = _http_request("GET", "/api/status")
    for k, v in scope_extra["headers"]:
        req.scope["headers"].append((k, v))
    assert asyncio.run(main.require_api_key(req, nxt)) == "next"

    # OPTIONS (CORS preflight) siempre pasa.
    assert asyncio.run(main.require_api_key(_http_request("OPTIONS", "/api/status"), nxt)) == "next"


def test_per_key_bucket_mapping_and_hashed_id(monkeypatch):
    import backend.main as main

    monkeypatch.setattr(main, "API_KEY", "sekrit-key-1234")
    assert main._key_rate_limit_bucket("POST", "/api/scans") is main._key_mutation_limiter
    assert main._key_rate_limit_bucket("GET", "/api/status") is main._key_read_limiter
    # Sin auth activo no hay bucket por key.
    monkeypatch.setattr(main, "API_KEY", "")
    assert main._key_rate_limit_bucket("POST", "/api/scans") is None

    monkeypatch.setattr(main, "API_KEY", "sekrit-key-1234")
    kid = main._key_rate_limit_id(_http_request("GET", "/api/status", key="sekrit-key-1234"))
    assert kid.startswith("k:") and len(kid) == 2 + 32
    # La clave cruda no aparece en el id (solo su sha256).
    assert "sekrit" not in kid
    # Sin key presentada: None (el 401 lo responde auth; el bucket IP sigue).
    assert main._key_rate_limit_id(_http_request("GET", "/api/status")) is None


def test_middleware_429_per_key_with_retry_after(monkeypatch):
    from backend.ratelimit import RateLimiter

    import backend.main as main

    monkeypatch.setattr(main, "API_KEY", "sekrit-key-1234")
    fresh = RateLimiter(3, 60.0, clock=FrozenClock())
    monkeypatch.setattr(main, "_key_read_limiter", fresh)

    nxt = CallNext()
    req = _http_request("GET", "/api/status", key="sekrit-key-1234")
    for _ in range(3):
        assert asyncio.run(main.rate_limit(req, nxt)) == "next"
    resp = asyncio.run(main.rate_limit(req, nxt))
    assert resp.status_code == 429
    assert json.loads(resp.body)["detail"] == "Rate limit exceeded for this API key"
    assert int(resp.headers["retry-after"]) >= 1
    # Otra key: presupuesto propio.
    other = _http_request("GET", "/api/status", key="otra-key-5678")
    assert asyncio.run(main.rate_limit(other, nxt)) == "next"
