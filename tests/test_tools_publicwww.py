"""OSINT backlog: publicwww_search tool + findings adapter (no network)."""
import asyncio

import backend.findings as findings
import backend.tools.osint as osint


def _run(coro):
    return asyncio.run(coro)


def _stub(monkeypatch, rows=None, calls=None):
    async def fake_query(domain):
        if calls is not None:
            calls.append(domain)
        return rows

    monkeypatch.setattr(osint, "_publicwww_query", fake_query)


# ── tool ────────────────────────────────────────────────────────
def test_ip_target_rejected(monkeypatch):
    _stub(monkeypatch, rows=[{"hostname": "a.example.com"}])
    result = _run(osint.publicwww_search("1.2.3.4"))
    assert "requires a domain" in result["error"]


def test_query_failure_degrades_to_error(monkeypatch):
    _stub(monkeypatch, rows=None)
    result = _run(osint.publicwww_search("example.com"))
    assert result["target"] == "example.com"
    assert result["error"] == "PublicWWW API unavailable or returned an error"


def test_success_aggregates_hosts_techs_urls(monkeypatch):
    calls = []
    rows = [
        {"hostname": "z.example.com", "url": "https://z.example.com/a",
         "tech": {"name": "Nginx"}},
        {"hostname": "m.example.com", "url": "https://m.example.com/b",
         "tech": {"name": "WordPress"}},
        {"hostname": "z.example.com", "url": "https://z.example.com/c"},
    ]
    _stub(monkeypatch, rows=rows, calls=calls)
    result = _run(osint.publicwww_search("example.com"))
    assert calls == ["example.com"]
    assert result["count"] == 3
    assert result["hosts"] == ["m.example.com", "z.example.com"]
    assert result["technologies"] == ["Nginx", "WordPress"]
    assert len(result["urls"]) == 3


def test_target_normalization(monkeypatch):
    _stub(monkeypatch, rows=[])
    result = _run(osint.publicwww_search("HTTPS://Example.COM:443/path?q=1"))
    assert result["target"] == "example.com"


def test_empty_rows_is_not_an_error(monkeypatch):
    _stub(monkeypatch, rows=[])
    result = _run(osint.publicwww_search("example.com"))
    assert "error" not in result
    assert result["count"] == 0
    assert result["hosts"] == []


def test_malformed_rows_dropped(monkeypatch):
    _stub(monkeypatch, rows=[
        "not-a-dict",
        {"hostname": "a.example.com"},
        {"hostname": None, "url": "", "tech": "nope"},
        {"hostname": "b.example.com", "tech": {"name": "Apache"}},
    ])
    result = _run(osint.publicwww_search("example.com"))
    assert result["hosts"] == ["a.example.com", "b.example.com"]
    assert result["technologies"] == ["Apache"]


def test_url_cap_at_200(monkeypatch):
    rows = [{"hostname": f"s{i}.example.com", "url": f"https://x/{i}"}
            for i in range(300)]
    _stub(monkeypatch, rows=rows)
    result = _run(osint.publicwww_search("example.com"))
    assert len(result["urls"]) == 200


# ── findings adapter ─────────────────────────────────────────────
def test_adapter_sensitive_and_profile():
    result = {
        "target": "example.com", "count": 3,
        "hosts": ["staging.example.com", "www.example.com"],
        "technologies": ["Nginx"],
    }
    out = findings.extract_findings("publicwww_search", result, "example.com")
    assert [f.severity for f in out] == [
        findings.Severity.MEDIUM, findings.Severity.INFO,
    ]
    assert out[0].title == "Sensitive subdomain name: staging.example.com"
    assert out[0].confidence == 0.7
    assert out[1].evidence["technologies"] == ["Nginx"]


def test_adapter_no_sensitive_only_profile():
    result = {"target": "example.com", "count": 2,
              "hosts": ["www.example.com", "mail.example.com"]}
    out = findings.extract_findings("publicwww_search", result, "example.com")
    assert len(out) == 1
    assert out[0].severity == findings.Severity.INFO


def test_adapter_caps_at_10():
    labels = ["staging", "backup", "qa", "git", "internal", "vpn",
              "sandbox", "demo", "debug", "tmp", "ci", "jenkins"]
    hosts = [f"{lab}.example.com" for lab in labels]
    result = {"target": "example.com", "count": len(hosts), "hosts": hosts}
    out = findings.extract_findings("publicwww_search", result, "example.com")
    assert len(out) == 10


def test_adapter_empty_and_error_no_finding():
    assert findings.extract_findings("publicwww_search", {}, "example.com") == []
    assert findings.extract_findings(
        "publicwww_search", {"target": "example.com", "error": "boom"},
        "example.com") == []
