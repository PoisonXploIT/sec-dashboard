"""Tests for target validation / SSRF protection (backend/validators.py)."""
import pytest

from backend import validators


# ── Local mode (default) ────────────────────────────────────────

def test_empty_host_rejected():
    ok, reason = validators.validate_target("")
    assert not ok
    assert "empty" in reason.lower()


def test_whitespace_host_rejected():
    ok, _ = validators.validate_target("   ")
    assert not ok


def test_local_mode_allows_private_ip(monkeypatch):
    monkeypatch.delenv("SEC_DASHBOARD_REMOTE", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    ok, _ = validators.validate_target("10.0.0.5")
    assert ok


def test_local_mode_allows_localhost(monkeypatch):
    monkeypatch.delenv("SEC_DASHBOARD_REMOTE", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    ok, _ = validators.validate_target("localhost")
    assert ok


def test_local_mode_allows_metadata_host(monkeypatch):
    monkeypatch.delenv("SEC_DASHBOARD_REMOTE", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    ok, reason = validators.validate_target("169.254.169.254")
    assert ok
    assert "local mode" in reason


def test_public_ip_always_valid(monkeypatch):
    monkeypatch.setenv("SEC_DASHBOARD_REMOTE", "1")
    ok, _ = validators.validate_target("8.8.8.8")
    assert ok


# ── Remote mode (SSRF protection enforced) ───────────────────────

@pytest.fixture
def remote(monkeypatch):
    monkeypatch.setenv("SEC_DASHBOARD_REMOTE", "1")
    return True


def test_remote_blocks_private_ip(remote):
    ok, reason = validators.validate_target("10.0.0.5")
    assert not ok
    assert "SSRF" in reason


def test_remote_blocks_loopback_ip(remote):
    ok, _ = validators.validate_target("127.0.0.1")
    assert not ok


def test_remote_blocks_link_local_ip(remote):
    ok, _ = validators.validate_target("169.254.1.1")
    assert not ok


def test_remote_blocks_metadata_ip(remote):
    ok, reason = validators.validate_target("169.254.169.254")
    assert not ok
    assert "Metadata" in reason


def test_remote_blocks_localhost_name(remote):
    ok, _ = validators.validate_target("localhost")
    assert not ok


def test_remote_blocks_internal_tld(remote):
    ok, _ = validators.validate_target("app.internal")
    assert not ok


def test_remote_mode_autodetect_via_port(monkeypatch):
    monkeypatch.delenv("SEC_DASHBOARD_REMOTE", raising=False)
    monkeypatch.setenv("PORT", "8444")
    assert validators.is_remote_mode() is True
    ok, _ = validators.validate_target("192.168.1.10")
    assert not ok
