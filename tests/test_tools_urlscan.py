"""OSINT backlog: urlscan_lookup tool + findings adapter (no network)."""
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

    monkeypatch.setattr(osint, "_urlscan_query", fake_query)


def _row(domain="a.example.com", canonical_task="a.example.com"):
    return {
        "task": {"domain": domain, "time": "2026-08-01T00:00:00Z"},
        "canonical": {"task": {"url": canonical_task},
                      "page": {"url": "github.com/login"}},
        "page": {"ip": "1.2.3.4", "server": "github.com"},
    }


# ── tool ────────────────────────────────────────────────────────
def test_ip_target_rejected(monkeypatch):
    _stub(monkeypatch, rows=[_row()])
    result = _run(osint.urlscan_lookup("1.2.3.4"))
    assert "requires a domain" in result["error"]


def test_query_failure_degrades_to_error(monkeypatch):
    _stub(monkeypatch, rows=None)
    result = _run(osint.urlscan_lookup("example.com"))
    assert result["target"] == "example.com"
    assert result["error"] == "URLScan API unavailable or returned an error"


def test_success_aggregates_hosts(monkeypatch):
    calls = []
    rows = [
        _row("z.example.com", "z.example.com"),
        _row("m.example.com", "m.example.com"),
        _row("z.example.com", "z.example.com"),  # duplicate scan
    ]
    _stub(monkeypatch, rows=rows, calls=calls)
    result = _run(osint.urlscan_lookup("example.com"))
    assert calls == ["example.com"]
    assert result["count"] == 3
    assert result["hosts"] == ["m.example.com", "z.example.com"]


def test_target_normalization(monkeypatch):
    _stub(monkeypatch, rows=[])
    result = _run(osint.urlscan_lookup("HTTPS://Example.COM:443/path?q=1"))
    assert result["target"] == "example.com"


def test_empty_rows_is_not_an_error(monkeypatch):
    _stub(monkeypatch, rows=[])
    result = _run(osint.urlscan_lookup("example.com"))
    assert "error" not in result
    assert result["count"] == 0
    assert result["hosts"] == []


def test_malformed_rows_dropped(monkeypatch):
    rows = [
        "not-a-dict",
        {"task": None, "canonical": "nope"},
        {"page": {"ip": "9.9.9.9"}},  # no task/canonical at all
        _row("b.example.com", "b.example.com"),
    ]
    _stub(monkeypatch, rows=rows)
    result = _run(osint.urlscan_lookup("example.com"))
    assert result["hosts"] == ["b.example.com"]


def test_canonical_page_path_is_not_a_host(monkeypatch):
    # canonical.page.url can be a post-redirect path ("github.com/login");
    # only task.domain and canonical.task.url feed the host inventory.
    rows = [{
        "task": {"domain": None},
        "canonical": {"task": {"url": ""}, "page": {"url": "x"}},
    }]
    _stub(monkeypatch, rows=rows)
    result = _run(osint.urlscan_lookup("example.com"))
    assert result["hosts"] == []


def test_host_cap_at_1000(monkeypatch):
    rows = [_row(f"s{i}.example.com") for i in range(1200)]
    _stub(monkeypatch, rows=rows)
    result = _run(osint.urlscan_lookup("example.com"))
    assert len(result["hosts"]) == 1000


# ── findings adapter ─────────────────────────────────────────────
def test_adapter_sensitive_and_profile():
    result = {
        "target": "example.com", "count": 3,
        "hosts": ["staging.example.com", "www.example.com"],
    }
    out = findings.extract_findings("urlscan_lookup", result, "example.com")
    assert [f.severity for f in out] == [
        findings.Severity.MEDIUM, findings.Severity.INFO,
    ]
    assert out[0].title == "Sensitive subdomain name: staging.example.com"
    assert out[0].confidence == 0.7
    assert out[1].evidence["top_hosts"] == ["staging.example.com",
                                             "www.example.com"]


def test_adapter_no_sensitive_only_profile():
    result = {"target": "example.com", "count": 2,
              "hosts": ["www.example.com", "mail.example.com"]}
    out = findings.extract_findings("urlscan_lookup", result, "example.com")
    assert len(out) == 1
    assert out[0].severity == findings.Severity.INFO


def test_adapter_caps_at_10():
    labels = ["staging", "backup", "qa", "git", "internal", "vpn",
              "sandbox", "demo", "debug", "tmp", "ci", "jenkins"]
    hosts = [f"{lab}.example.com" for lab in labels]
    result = {"target": "example.com", "count": len(hosts), "hosts": hosts}
    out = findings.extract_findings("urlscan_lookup", result, "example.com")
    assert len(out) == 10


def test_adapter_empty_and_error_no_finding():
    assert findings.extract_findings("urlscan_lookup", {}, "example.com") == []
    assert findings.extract_findings(
        "urlscan_lookup", {"target": "example.com", "error": "boom"},
        "example.com") == []
