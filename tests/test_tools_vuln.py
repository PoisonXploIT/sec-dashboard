"""Tests for pure logic in backend/tools/vuln.py (network calls stubbed)."""
import asyncio

import pytest

from backend.tools import vuln


class _OfflineSession:
    """aiohttp.ClientSession stand-in that fails immediately (no network)."""

    def __init__(self, *a, **kw):
        raise RuntimeError("offline test")


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(vuln.aiohttp, "ClientSession", _OfflineSession)


def _run(coro):
    return asyncio.run(coro)


def test_hash_checker_rejects_unknown_format():
    res = _run(vuln.hash_checker("not-a-hash"))
    assert "error" in res


def test_hash_checker_detects_md5_without_network(monkeypatch):
    # No API keys configured -> MalwareBazaar reports missing key, no request made.
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    res = _run(vuln.hash_checker("d41d8cd98f00b204e9800998ecf8427e"))
    assert res["hash_type"] == "MD5"
    assert "MalwareBazaar" in res["sources"]


def test_password_audit_common_password_flagged():
    res = _run(vuln.password_audit(password="password123"))
    assert res["analysis"]["is_common"] is True
    # 11 chars, lower+digit only, common list hit: score 4/11 -> Weak offline.
    assert res["score"] == "4/11"
    assert res["strength"] == "Weak"
    assert any("commonly used" in r for r in res["recommendations"])


def test_password_audit_strong_password():
    pwd = "Tr0ubadour&Correct$Horse-9Xk#2026"
    res = _run(vuln.password_audit(password=pwd))
    a = res["analysis"]
    assert a["has_uppercase"] and a["has_lowercase"] and a["has_digits"] and a["has_special"]
    assert a["is_common"] is False
    assert a["entropy"] > 40
    # score is "n/11"
    assert res["score"].endswith("/11")


def test_password_audit_missing_input():
    res = _run(vuln.password_audit(password=""))
    assert "error" in res


def test_password_recommendations_pure():
    analysis = {
        "length": 6, "has_uppercase": False, "has_lowercase": True,
        "has_digits": False, "has_special": False, "is_common": False,
    }
    recs = vuln._password_recommendations(analysis, None)
    assert any("12" in r for r in recs)  # length advice
    assert any("uppercase" in r.lower() for r in recs)


def test_password_recommendations_breached():
    analysis = {"length": 20, "has_uppercase": True, "has_lowercase": True,
                "has_digits": True, "has_special": True, "is_common": False}
    recs = vuln._password_recommendations(analysis, 1500)
    assert any("1,500" in r for r in recs)
