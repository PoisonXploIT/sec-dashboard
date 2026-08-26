"""F1-TAKEOVER: subdomain_takeover tool + findings adapter (no network)."""
import asyncio

import backend.findings as findings
import backend.tools.network as net


def _run(coro):
    return asyncio.run(coro)


# ── _match_platform ───────────────────────────────────────────
def test_match_platform_github_pages():
    assert net._match_platform("old-2019.github.io") == "github_pages"
    assert net._match_platform("site.githubpages.dev") == "github_pages"


def test_match_platform_heroku_and_s3():
    assert net._match_platform("app.herokuapp.com") == "heroku"
    assert net._match_platform("x.onheroku.com") == "heroku"
    assert net._match_platform("b.s3.amazonaws.com") == "s3"
    assert net._match_platform("b.s3.us-east-1.amazonaws.com") == "s3"
    assert net._match_platform("site.website.amazonaws.com") == "s3"


def test_match_platform_no_match():
    assert net._match_platform("cdn.cloudflare.net") is None
    assert net._match_platform("") is None
    assert net._match_platform(None) is None


# ── handler (stubbed DNS + HTTP) ────────────────────────────────
def _stub(monkeypatch, subs, dns_map, status=404):
    async def fake_ct(domain, **kw):
        return {"target": domain, "subdomains": subs}

    async def fake_dns(host):
        return dns_map[host]

    async def fake_probe(sub):
        return status

    monkeypatch.setattr(net, "ct_logs", fake_ct)
    monkeypatch.setattr(net, "_takeover_dns", fake_dns)
    monkeypatch.setattr(net, "_takeover_probe", fake_probe)


def test_handler_finds_dangling_github_pages(monkeypatch):
    _stub(monkeypatch, ["old.example.com"], {
        "old.example.com": {"cname": "old-2019.github.io", "a_resolved": False, "nxdomain": False},
    })
    result = _run(net.subdomain_takeover("example.com"))
    assert result["count"] == 1
    t = result["takeovers"][0]
    assert t["sub"] == "old.example.com"
    assert t["platform"] == "github_pages"
    assert t["dangling"] is True


def test_handler_active_sub_not_flagged(monkeypatch):
    _stub(monkeypatch, ["app.example.com"], {
        "app.example.com": {"cname": "app.herokuapp.com", "a_resolved": True, "nxdomain": False},
    }, status=200)
    result = _run(net.subdomain_takeover("example.com"))
    assert result["count"] == 0
    assert result["candidates_with_cname"] == 1


def test_handler_skips_nxdomain_and_foreign_cnames(monkeypatch):
    _stub(monkeypatch, ["gone.example.com", "int.example.com"], {
        "gone.example.com": {"cname": None, "a_resolved": False, "nxdomain": True},
        "int.example.com": {"cname": "internal.corp-dns.net", "a_resolved": True, "nxdomain": False},
    })
    result = _run(net.subdomain_takeover("example.com"))
    assert result["count"] == 0
    assert result["candidates_with_cname"] == 1


def test_handler_ct_error_degrades_not_breaks(monkeypatch):
    async def fake_ct(domain, **kw):
        return {"target": domain, "subdomains": [], "error": "crt.sh timeout"}

    monkeypatch.setattr(net, "ct_logs", fake_ct)
    result = _run(net.subdomain_takeover("example.com"))
    assert result["count"] == 0
    assert result["checked"] == 0
    assert result["ct_error"] == "crt.sh timeout"


def test_handler_rejects_ip_target():
    result = _run(net.subdomain_takeover("10.0.0.5"))
    assert "error" in result


def test_handler_normalizes_url_input(monkeypatch):
    async def fake_ct(domain, **kw):
        assert domain == "example.com"
        return {"target": domain, "subdomains": []}

    monkeypatch.setattr(net, "ct_logs", fake_ct)
    result = _run(net.subdomain_takeover("https://Example.com:8443/path?q=1"))
    assert result["domain"] == "example.com"


# ── findings adapter ───────────────────────────────────────────
def test_adapter_dangling_is_critical_and_dedup_by_sub():
    result = {
        "takeovers": [
            {"sub": "old.example.com", "cname": "a.github.io", "platform": "github_pages"},
            {"sub": "old.example.com", "cname": "a.github.io", "platform": "github_pages"},
            {"sub": "bak.example.com", "cname": "b.s3.amazonaws.com", "platform": "s3"},
        ],
    }
    out = findings.extract_findings("subdomain_takeover", result, "example.com")
    assert len(out) == 2
    assert all(f.severity == findings.Severity.CRITICAL for f in out)
    assert {f.evidence["cname"] for f in out} == {"a.github.io", "b.s3.amazonaws.com"}


def test_adapter_empty_and_no_takeovers():
    assert findings.extract_findings("subdomain_takeover", {}, "example.com") == []
    assert findings.extract_findings("subdomain_takeover", {"takeovers": []}, "x") == []
