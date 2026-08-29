"""In-memory rate limiting (backend/ratelimit.py) y su cableado en main.py.

Sin red. El RateLimiter corre contra un reloj manual (tiempo congelado sin
monkeypatch de time.monotonic); el middleware se prueba directamente con
Request de starlette fabricados y un call_next stub, mismo estilo de llamada
directa que el resto de la suite.
"""
import asyncio
import json

from starlette.requests import Request

from backend.ratelimit import RateLimiter


class FrozenClock:
    """Reloj manual: avanza solo cuando el test lo dice."""

    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


# ── RateLimiter (unitario) ─────────────────────────────────────


def test_allows_up_to_limit_then_rejects():
    lim = RateLimiter(3, 60.0, clock=FrozenClock())
    for _ in range(3):
        assert lim.check("a") == (True, 0)
    allowed, retry = lim.check("a")
    assert not allowed
    assert retry >= 1


def test_sliding_window_expires_per_hit():
    clock = FrozenClock()
    lim = RateLimiter(3, 60.0, clock=clock)
    for t in (0.0, 1.0, 2.0):
        clock.t = t
        assert lim.check("a")[0]
    # A t=59 nada ha expirado: sigue rechazando y retry apunta al hit más viejo.
    clock.t = 59.0
    allowed, retry = lim.check("a")
    assert not allowed
    assert retry == 1
    # El primer hit (t=0) expira a t=60: se libera un hueco.
    clock.t = 60.5
    assert lim.check("a")[0]


def test_rejected_requests_do_not_extend_window():
    clock = FrozenClock()
    lim = RateLimiter(2, 60.0, clock=clock)
    clock.t = 0.0
    assert lim.check("a")[0]
    clock.t = 1.0
    assert lim.check("a")[0]
    # Rechazados: no se registran, no alargan la prohibición.
    for t in (2.0, 3.0, 4.0):
        clock.t = t
        assert not lim.check("a")[0]
    # A t=61 el primer hit ha expirado: permitido de nuevo.
    clock.t = 61.0
    assert lim.check("a")[0]


def test_retry_after_points_at_oldest_expiry():
    clock = FrozenClock()
    lim = RateLimiter(2, 60.0, clock=clock)
    clock.t = 0.0
    lim.check("a")
    clock.t = 10.0
    lim.check("a")
    clock.t = 20.0
    allowed, retry = lim.check("a")
    assert not allowed
    # El hit más viejo (t=0) expira a t=60.
    assert retry == 40


def test_keys_are_independent():
    lim = RateLimiter(1, 60.0, clock=FrozenClock())
    assert lim.check("a")[0]
    assert not lim.check("a")[0]
    # Otro IP: presupuesto propio.
    assert lim.check("b")[0]


def test_gc_binds_memory_for_many_keys():
    clock = FrozenClock()
    lim = RateLimiter(5, 60.0, clock=clock)
    for i in range(4100):
        assert lim.check(f"ip-{i}")[0]
    # Avanzar mas de 2*window y pedir una clave nueva barre los stale.
    clock.advance(200)
    assert lim.check("new-ip")[0]
    assert "ip-0" not in lim._hits
    assert len(lim._hits) <= 2


# ── Cableado en main.py ─────────────────────────────────────────


def test_bucket_mapping_and_limits():
    import backend.main as main

    # Limites del diseno: mutacion estricta, lectura permisiva.
    assert main.MUTATION_RATE_LIMIT == 30
    assert main.READ_RATE_LIMIT == 600
    assert main._mutation_limiter.limit == 30
    assert main._read_limiter.limit == 600

    mut = main._rate_limit_bucket("POST", "/api/scans")
    assert mut is main._mutation_limiter
    assert main._rate_limit_bucket("POST", "/api/pipelines") is mut
    assert main._rate_limit_bucket("POST", "/api/targets") is mut

    read = main._rate_limit_bucket("GET", "/api/status")
    assert read is main._read_limiter
    # Cualquier GET de /api/* cae en el bucket de lectura.
    assert main._rate_limit_bucket("GET", "/api/scans/5/export/json") is read

    # Mutacion extendida: uploads (disco), config proxy/Splunk (SSRF)
    # y webhooks (sondas salientes) comparten el bucket estricto.
    assert main._rate_limit_bucket("POST", "/api/upload/cff") is mut
    assert main._rate_limit_bucket("POST", "/api/upload/pcap") is mut
    assert main._rate_limit_bucket("POST", "/api/proxy") is mut
    assert main._rate_limit_bucket("POST", "/api/splunk") is mut
    assert main._rate_limit_bucket("POST", "/api/webhooks") is mut
    assert main._rate_limit_bucket("POST", "/api/webhooks/1/test") is mut
    # DELETE es mutacion; /api/reset lleva su bucket horario estricto.
    assert main._rate_limit_bucket("DELETE", "/api/targets/1") is mut
    assert main._rate_limit_bucket("DELETE", "/api/scans/5") is mut
    assert main._rate_limit_bucket("DELETE", "/api/reset") is main._reset_limiter
    assert main._reset_limiter.limit == main.RESET_RATE_LIMIT == 5

    # Sin limitar: otros metodos, sub-rutas y no-API.
    assert main._rate_limit_bucket("POST", "/api/scans/5/cancel") is None
    assert main._rate_limit_bucket("GET", "/") is None


def _http_request(method, path, host="203.0.113.7"):
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path,
        "headers": [],
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


def test_middleware_429_after_limit_with_retry_after(monkeypatch):
    import backend.main as main

    # Limpiador fresco con reloj congelado: determinismo sin dormir.
    fresh = RateLimiter(30, 60.0, clock=FrozenClock())
    monkeypatch.setattr(main, "_mutation_limiter", fresh)

    nxt = CallNext()
    req = _http_request("POST", "/api/scans")

    # Los primeros 30 pasan.
    for _ in range(30):
        assert asyncio.run(main.rate_limit(req, nxt)) == "next"
    assert nxt.calls == 30

    # El 31: 429 con Retry-After y body coherente; call_next NO se invoca.
    resp = asyncio.run(main.rate_limit(req, nxt))
    assert resp.status_code == 429
    assert json.loads(resp.body)["detail"] == "Rate limit exceeded"
    assert int(resp.headers["retry-after"]) >= 1
    assert nxt.calls == 30

    # Otro IP: bucket propio, sigue pasando.
    other = _http_request("POST", "/api/scans", host="198.51.100.9")
    assert asyncio.run(main.rate_limit(other, nxt)) == "next"


def test_middleware_passes_unlimited_requests(monkeypatch):
    import backend.main as main

    fresh = RateLimiter(30, 60.0, clock=FrozenClock())
    monkeypatch.setattr(main, "_mutation_limiter", fresh)

    nxt = CallNext()
    # POST /api/scans/5/cancel no esta en ningun bucket: siempre pasa.
    for _ in range(40):
        resp = asyncio.run(main.rate_limit(_http_request("POST", "/api/scans/5/cancel"), nxt))
        assert resp == "next"
    assert nxt.calls == 40
