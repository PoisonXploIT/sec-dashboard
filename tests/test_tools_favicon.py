"""F1-FAVICON: favicon_fingerprint tool + findings adapter (no network).

El fetch se stubea igual que en test_tools_secret_leak_scan; la base de
hashes se apunta a un JSON temporal con _reset_db_cache. La base real
(data/favicon_hashes.json) solo se valida su integridad, sin red.
"""
import asyncio
import hashlib
from urllib.parse import urlparse

import backend.findings as findings
import backend.tools.favicon as favicon


def _run(coro):
    return asyncio.run(coro)


KNOWN = b"FAKE-ICON-BYTES"
OTHER = b"OTHER-BYTES"


def _use_db(monkeypatch, tmp_path, entries):
    import json

    path = tmp_path / "db.json"
    path.write_text(json.dumps(entries))
    monkeypatch.setattr(favicon, "FAVICON_DB_PATH", path)
    favicon._reset_db_cache()


def _stub(monkeypatch, bodies):
    """bodies: {path: (status, content_type, bytes)}; resto = 404 vacio."""
    async def fake_fetch(url, session):
        path = urlparse(url).path
        if path in bodies:
            return bodies[path]
        return 404, "", b""

    monkeypatch.setattr(favicon, "_favicon_fetch", fake_fetch)


def _entry(data: bytes, name="TestStack"):
    return {
        "name": name,
        "source": "https://example.org/favicon.ico",
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ── base real ───────────────────────────────────────────────────
def test_real_db_integrity():
    favicon._reset_db_cache()
    db = favicon._load_db()
    entries = [e for k, e in db.items() if len(k) == 32]  # solo claves md5
    assert len(entries) >= 6
    names = {e["name"] for e in entries}
    assert "WordPress" in names and "Shopify" in names
    for e in entries:
        assert len(e["md5"]) == 32 and len(e["sha256"]) == 64
        assert e["source"].startswith("https://")


# ── handler (stubbed HTTP) ───────────────────────────────────────
def test_handler_match_sets_stack(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, [_entry(KNOWN)])
    _stub(monkeypatch, {"/favicon.ico": (200, "image/x-icon", KNOWN)})
    res = _run(favicon.favicon_fingerprint("example.com"))
    assert res["target"] == "https://example.com"
    assert len(res["icons"]) == 1
    icon = res["icons"][0]
    assert icon["md5"] == hashlib.md5(KNOWN).hexdigest()
    assert icon["sha256"] == hashlib.sha256(KNOWN).hexdigest()
    assert res["stack"] == "TestStack"
    assert res["matches"][0]["path"] == "/favicon.ico"


def test_handler_unknown_icon_no_match(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, [_entry(KNOWN)])
    _stub(monkeypatch, {"/apple-touch-icon.png": (200, "image/png", OTHER)})
    res = _run(favicon.favicon_fingerprint("example.com"))
    assert len(res["icons"]) == 1
    assert res["matches"] == [] and res["stack"] is None


def test_handler_no_icons(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, [_entry(KNOWN)])
    _stub(monkeypatch, {})
    res = _run(favicon.favicon_fingerprint("https://example.com/any/path"))
    assert res["icons"] == [] and res["matches"] == [] and res["stack"] is None
    # La base queda en el origen, sin la path de la URL
    assert res["target"] == "https://example.com"


def test_fetch_failure_returns_empty_triple(monkeypatch):
    class Boom:
        async def __aenter__(self):
            raise OSError("no network")

        async def __aexit__(self, *a):
            return False

    async def main():
        return await favicon._favicon_fetch("https://x/favicon.ico", Boom())

    assert _run(main()) == (0, "", b"")


# ── findings adapter ────────────────────────────────────────────
def test_adapter_match_is_info_finding():
    res = {
        "matches": [{"stack": "TestStack", "path": "/favicon.ico", "md5": "a" * 32,
                    "source": "https://example.org/favicon.ico"}],
        "icons": [],
    }
    out = findings.extract_findings("favicon_fingerprint", res, "example.com")
    assert len(out) == 1
    f = out[0]
    assert f.severity.value == "info" and f.tool == "favicon_fingerprint"
    assert "TestStack" in f.title


def test_adapter_unknown_icon_carries_hashes():
    res = {"matches": [], "icons": [
        {"path": "/favicon.ico", "md5": "b" * 32, "sha256": "c" * 64}]}
    out = findings.extract_findings("favicon_fingerprint", res, "example.com")
    assert len(out) == 1
    assert out[0].evidence["md5"] == "b" * 32


def test_adapter_no_icons_no_findings():
    out = findings.extract_findings(
        "favicon_fingerprint", {"matches": [], "icons": []}, "example.com")
    assert out == []
