"""OSINT backlog: greynoise_lookup tool + findings adapter (no network)."""
import asyncio
import socket

import backend.findings as findings
import backend.tools.osint as osint


def _run(coro):
    return asyncio.run(coro)


def _stub(monkeypatch, data=None, calls=None, key=""):
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)

    async def fake_query(ip, k):
        if calls is not None:
            calls.append((ip, k))
        return data

    monkeypatch.setattr(osint, "_greynoise_query", fake_query)


# ── tool ────────────────────────────────────────────────────────
def test_unresolvable_target(monkeypatch):
    _stub(monkeypatch, data={})

    def fake_resolve(name):
        raise socket.gaierror("no")

    monkeypatch.setattr(osint.socket, "gethostbyname", fake_resolve)
    result = _run(osint.greynoise_lookup("nope.invalid"))
    assert "Could not resolve" in result["error"]


def test_no_key_still_queries_public_api(monkeypatch):
    calls = []
    _stub(monkeypatch,
         data={"ip": "1.2.3.4", "noise": False, "riot": False,
              "message": "IP not observed scanning the internet."},
         calls=calls)
    result = _run(osint.greynoise_lookup("1.2.3.4"))
    assert calls == [("1.2.3.4", "")]  # public endpoint, empty key ok
    assert result["found"] is False


def test_key_passed_when_set(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "K")
    calls = []

    async def fake_query(ip, k):
        calls.append((ip, k))
        return {"ip": ip, "noise": True, "riot": False,
                "classification": "malicious", "name": "x",
                "last_seen": "2025-01-01"}

    monkeypatch.setattr(osint, "_greynoise_query", fake_query)
    result = _run(osint.greynoise_lookup("1.2.3.4"))
    assert calls == [("1.2.3.4", "K")]
    assert result["found"] is True


def test_query_failure_degrades_to_error(monkeypatch):
    _stub(monkeypatch, data=None)
    result = _run(osint.greynoise_lookup("1.2.3.4"))
    assert result["error"] == "GreyNoise API unavailable or returned an error"


def test_no_data_is_not_an_error(monkeypatch):
    _stub(monkeypatch,
         data={"ip": "1.2.3.4", "noise": False, "riot": False,
              "message": "IP not observed scanning the internet."})
    result = _run(osint.greynoise_lookup("1.2.3.4"))
    assert "error" not in result
    assert result["found"] is False


def test_auth_or_rate_limit_body_is_error(monkeypatch):
    _stub(monkeypatch, data={"message": "Authentication Error has Occurred"})
    result = _run(osint.greynoise_lookup("1.2.3.4"))
    assert "Authentication" in result["error"]


def test_noise_malicious_parsed(monkeypatch):
    _stub(monkeypatch,
         data={"ip": "5.6.7.8", "noise": True, "riot": False,
              "classification": "malicious", "name": "unknown",
              "last_seen": "2025-01-02", "message": "Success"})
    result = _run(osint.greynoise_lookup("5.6.7.8"))
    assert result["found"] is True
    assert result["noise"] is True
    assert result["classification"] == "malicious"
    assert result["last_seen"] == "2025-01-02"


def test_riot_benign_parsed(monkeypatch):
    _stub(monkeypatch,
         data={"ip": "1.1.1.1", "noise": False, "riot": True,
              "classification": "benign", "name": "Cloudflare",
              "last_seen": "2025-01-03"})
    result = _run(osint.greynoise_lookup("1.1.1.1"))
    assert result["found"] is True
    assert result["riot"] is True
    assert result["noise"] is False


# ── findings adapter ─────────────────────────────────────────────
def test_adapter_malicious_scanner_high():
    result = {"target": "x", "ip": "5.6.7.8", "found": True,
              "noise": True, "riot": False, "classification": "malicious",
              "name": "", "last_seen": "2025-01-02"}
    out = findings.extract_findings("greynoise_lookup", result, "5.6.7.8")
    assert len(out) == 1
    assert out[0].severity == findings.Severity.HIGH
    assert out[0].confidence == 0.8


def test_adapter_benign_scanner_low():
    result = {"target": "x", "ip": "5.6.7.8", "found": True,
              "noise": True, "riot": False, "classification": "benign",
              "name": "", "last_seen": ""}
    out = findings.extract_findings("greynoise_lookup", result, "5.6.7.8")
    assert len(out) == 1
    assert out[0].severity == findings.Severity.LOW


def test_adapter_riot_only_info():
    result = {"target": "x", "ip": "1.1.1.1", "found": True,
              "noise": False, "riot": True, "classification": "benign",
              "name": "Cloudflare", "last_seen": ""}
    out = findings.extract_findings("greynoise_lookup", result, "1.1.1.1")
    assert len(out) == 1
    assert out[0].severity == findings.Severity.INFO
    assert out[0].evidence["name"] == "Cloudflare"


def test_adapter_not_found_or_error_no_finding():
    assert findings.extract_findings("greynoise_lookup", {}, "1.2.3.4") == []
    assert findings.extract_findings(
        "greynoise_lookup", {"target": "x", "ip": "1.2.3.4",
                             "found": False}, "1.2.3.4") == []
    assert findings.extract_findings(
        "greynoise_lookup", {"target": "x", "error": "boom"}, "1.2.3.4") == []
