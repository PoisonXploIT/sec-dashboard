"""OSINT backlog: hunter_email_finder tool + findings adapter (no network)."""
import asyncio

import backend.findings as findings
import backend.tools.osint as osint


def _run(coro):
    return asyncio.run(coro)


def _stub(monkeypatch, rows=None, calls=None, key="K"):
    monkeypatch.setenv("HUNTER_API_KEY", "K")

    async def fake_query(domain, k):
        if calls is not None:
            calls.append((domain, k))
        return rows

    monkeypatch.setattr(osint, "_hunter_query", fake_query)


# ── tool ────────────────────────────────────────────────────────
def test_ip_target_rejected(monkeypatch):
    _stub(monkeypatch, rows=[])
    result = _run(osint.hunter_email_finder("1.2.3.4"))
    assert "requires a domain" in result["error"]


def test_no_key_degrades_to_error_without_query(monkeypatch):
    monkeypatch.delenv("HUNTER_API_KEY", raising=False)
    calls = []

    async def fake_query(domain, k):
        calls.append((domain, k))
        return [{"value": "a@example.com"}]

    monkeypatch.setattr(osint, "_hunter_query", fake_query)
    result = _run(osint.hunter_email_finder("example.com"))
    assert "HUNTER_API_KEY" in result["error"]
    assert calls == []  # no network attempt without a key


def test_query_failure_degrades_to_error(monkeypatch):
    _stub(monkeypatch, rows=None)
    result = _run(osint.hunter_email_finder("example.com"))
    assert result["error"] == "Hunter API unavailable or returned an error"


def test_success_dedupes_and_maps_fields(monkeypatch):
    calls = []
    _stub(monkeypatch, calls=calls, rows=[
        {"value": "Ciaran.Lee@Example.com", "confidence": 92,
         "type": "personal", "first_name": "Ciaran", "last_name": "Lee",
         "position": "Support Engineer", "decision_maker": False},
        {"value": "ciaran.lee@example.com"},  # duplicate after normalize
        {"no_value_key": True},               # malformed: dropped
        {"value": ""},                       # empty: dropped
    ])
    result = _run(osint.hunter_email_finder("example.com"))
    assert calls == [("example.com", "K")]
    assert "error" not in result
    assert result["count"] == 1
    top = result["emails"][0]
    assert top["email"] == "ciaran.lee@example.com"
    assert top["confidence"] == 92
    assert top["position"] == "Support Engineer"
    assert top["decision_maker"] is False


def test_target_normalization(monkeypatch):
    _stub(monkeypatch, rows=[])
    result = _run(osint.hunter_email_finder("HTTPS://Example.COM:443/path?q=1"))
    assert result["target"] == "example.com"


def test_empty_emails_is_not_an_error(monkeypatch):
    _stub(monkeypatch, rows=[])
    result = _run(osint.hunter_email_finder("example.com"))
    assert "error" not in result
    assert result["count"] == 0
    assert result["emails"] == []


def test_cap_at_100(monkeypatch):
    _stub(monkeypatch, rows=[{"value": f"u{i}@example.com"} for i in range(150)])
    result = _run(osint.hunter_email_finder("example.com"))
    assert result["count"] == 100


# ── findings adapter ─────────────────────────────────────────────
def test_adapter_sensitive_and_decision_maker():
    result = {
        "target": "example.com", "count": 4,
        "emails": [
            {"email": "admin@example.com", "confidence": 97},
            {"email": "ciaran.lee@example.com", "confidence": 92,
             "decision_maker": True, "position": "CEO"},
            {"email": "www@example.com", "confidence": 80},
        ],
    }
    out = findings.extract_findings("hunter_email_finder", result, "example.com")
    sevs = [f.severity for f in out]
    assert sevs.count(findings.Severity.MEDIUM) == 2
    assert sevs[-1] == findings.Severity.INFO  # profile last
    mediums = {f.evidence["email"] for f in out if f.severity == findings.Severity.MEDIUM}
    assert mediums == {"admin@example.com", "ciaran.lee@example.com"}


def test_adapter_no_sensitive_only_profile():
    result = {"target": "example.com", "count": 2,
              "emails": [{"email": "www@example.com"},
                         {"email": "mail@example.com"}]}
    out = findings.extract_findings("hunter_email_finder", result, "example.com")
    assert len(out) == 1
    assert out[0].severity == findings.Severity.INFO


def test_adapter_caps_at_10():
    emails = [{"email": f"u{i}@example.com", "decision_maker": True}
             for i in range(10)]
    result = {"target": "example.com", "count": len(emails), "emails": emails}
    out = findings.extract_findings("hunter_email_finder", result, "example.com")
    assert len(out) == 10


def test_adapter_empty_and_error_no_finding():
    assert findings.extract_findings("hunter_email_finder", {}, "example.com") == []
    assert findings.extract_findings(
        "hunter_email_finder", {"target": "example.com", "error": "boom"},
        "example.com") == []
