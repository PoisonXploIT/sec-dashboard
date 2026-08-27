"""OSINT backlog: wayback_urls tool + findings adapter (no network)."""
import asyncio

import backend.findings as findings
import backend.tools.web as web


def _run(coro):
    return asyncio.run(coro)


# ── host validation / limit clamping ────────────────────────────
def test_wayback_urls_rejects_ip_target():
    result = _run(web.wayback_urls("192.168.0.1"))
    assert "error" in result
    assert result["target"] == "192.168.0.1"


def test_wayback_urls_strips_path_and_port(monkeypatch):
    captured = {}

    async def fake_cdx(host, limit):
        captured["host"] = host
        captured["limit"] = limit
        return []

    monkeypatch.setattr(web, "_cdx_query", fake_cdx)
    result = _run(web.wayback_urls("http://example.com:8080/old/path?q=1"))
    assert result["target"] == "example.com"
    assert captured["host"] == "example.com"


def test_wayback_urls_clamps_limit(monkeypatch):
    captured = {}

    async def fake_cdx(host, limit):
        captured["limit"] = limit
        return []

    monkeypatch.setattr(web, "_cdx_query", fake_cdx)
    _run(web.wayback_urls("example.com", limit=99999))
    assert captured["limit"] == 1000
    _run(web.wayback_urls("example.com", limit="abc"))
    assert captured["limit"] == 500


# ── CDX parsing ──────────────────────────────────────────────────
def test_wayback_urls_parses_rows_paths_and_order(monkeypatch):
    rows = [
        # urlkey, timestamp, original, statuscode, digest, mimetype
        ["key3", "20140315171938", "https://example.com/admin.php?x=1", "200", "abc", "text/html"],
        ["key1", "20200101000000", "https://example.com/backup.sql", "200", "def", "application/sql"],
        ["key2", "20100505050505", "https://example.com/admin.php", "404", "ghi", "text/html"],
    ]

    async def fake_cdx(host, limit):
        return rows

    monkeypatch.setattr(web, "_cdx_query", fake_cdx)
    result = _run(web.wayback_urls("example.com"))

    assert result["target"] == "example.com"
    assert result["count"] == 3
    # Sorted by timestamp ascending (zero-padded: string order == time order)
    assert [u["timestamp"] for u in result["urls"]] == [
        "20100505050505", "20140315171938", "20200101000000",
    ]
    assert result["first_seen"] == "20100505050505"
    assert result["last_seen"] == "20200101000000"
    # /admin.php collapses both captures (query variants deduped by CDX)
    paths = {p["path"]: p["hits"] for p in result["paths"]}
    assert paths == {"/admin.php": 2, "/backup.sql": 1}
    # Most-hit path first
    assert result["paths"][0]["path"] == "/admin.php"


def test_wayback_urls_skips_malformed_rows(monkeypatch):
    rows = [
        ["short"],                       # too few columns
        ["k", "20200101000000", "ftp://example.com/x", "200", "d", "m"],  # non-http
        ["k", "20200101000000", "", "200", "d", "m"],                    # empty original
    ]

    async def fake_cdx(host, limit):
        return rows

    monkeypatch.setattr(web, "_cdx_query", fake_cdx)
    result = _run(web.wayback_urls("example.com"))
    assert result["count"] == 0
    assert result["urls"] == []
    assert result["first_seen"] is None
    assert result["last_seen"] is None


def test_wayback_urls_empty_domain(monkeypatch):
    async def fake_cdx(host, limit):
        return []

    monkeypatch.setattr(web, "_cdx_query", fake_cdx)
    result = _run(web.wayback_urls("nomanifest.example"))
    assert result["count"] == 0
    assert result["urls"] == []
    assert result["paths"] == []


def test_wayback_urls_failure_degrades_to_error(monkeypatch):
    async def fake_cdx(host, limit):
        return None

    monkeypatch.setattr(web, "_cdx_query", fake_cdx)
    result = _run(web.wayback_urls("example.com"))
    assert "error" in result
    assert result["target"] == "example.com"


# ── findings adapter ─────────────────────────────────────────────
def test_adapter_empty_result_no_finding():
    out = findings.extract_findings("wayback_urls", {"count": 0, "urls": []}, "example.com")
    assert out == []


def test_adapter_info_finding_with_top_paths():
    result = {
        "count": 2,
        "first_seen": "20100505050505",
        "last_seen": "20200101000000",
        "urls": [
            {"url": "https://example.com/a", "path": "/a", "status": "200", "timestamp": "20100505050505"},
            {"url": "https://example.com/b", "path": "/b", "status": "404", "timestamp": "20200101000000"},
        ],
        "paths": [{"path": "/a", "hits": 3}, {"path": "/b", "hits": 1}],
    }
    out = findings.extract_findings("wayback_urls", result, "example.com")
    assert len(out) == 1
    f = out[0]
    assert f.severity == findings.Severity.INFO
    assert f.category == "OSINT"
    assert f.tool == "wayback_urls"
    assert f.target == "example.com"
    assert f.evidence["count"] == 2
    assert f.evidence["top_paths"] == ["/a", "/b"]
