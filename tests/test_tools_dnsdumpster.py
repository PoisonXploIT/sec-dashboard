"""OSINT backlog: dnsdumpster_enum tool + findings adapter (no network)."""
import asyncio

import backend.findings as findings
import backend.tools.network as network


def _run(coro):
    return asyncio.run(coro)


def _stub(monkeypatch, subs=None, calls=None, key="K"):
    monkeypatch.setenv("DNSDUMPSTER_API_KEY", "K")

    async def fake_query(domain, k):
        if calls is not None:
            calls.append((domain, k))
        return subs

    monkeypatch.setattr(network, "_dnsdumpster_query", fake_query)


# ── tool ────────────────────────────────────────────────────────
def test_ip_target_rejected(monkeypatch):
    _stub(monkeypatch, subs=["a.example.com"])
    result = _run(network.dnsdumpster_enum("1.2.3.4"))
    assert "requires a domain" in result["error"]


def test_no_key_degrades_to_error_without_query(monkeypatch):
    monkeypatch.delenv("DNSDUMPSTER_API_KEY", raising=False)
    calls = []

    async def fake_query(domain, k):
        calls.append((domain, k))
        return ["a.example.com"]

    monkeypatch.setattr(network, "_dnsdumpster_query", fake_query)
    result = _run(network.dnsdumpster_enum("example.com"))
    assert "DNSDUMPSTER_API_KEY" in result["error"]
    assert calls == []  # no network attempt without a key


def test_query_failure_degrades_to_error(monkeypatch):
    _stub(monkeypatch, subs=None)
    result = _run(network.dnsdumpster_enum("example.com"))
    assert result["target"] == "example.com"
    assert result["error"] == "dnsdumpster API unavailable or returned an error"


def test_success_dedupes_and_sorts(monkeypatch):
    calls = []
    _stub(monkeypatch,
         subs=["z.example.com", "m.example.com", "z.example.com"],
         calls=calls)
    result = _run(network.dnsdumpster_enum("example.com"))
    assert calls == [("example.com", "K")]
    assert result["count"] == 2
    assert result["subdomains"] == ["m.example.com", "z.example.com"]


def test_target_normalization(monkeypatch):
    _stub(monkeypatch, subs=[])
    result = _run(network.dnsdumpster_enum("HTTPS://Example.COM:443/path?q=1"))
    assert result["target"] == "example.com"


def test_empty_subs_is_not_an_error(monkeypatch):
    _stub(monkeypatch, subs=[])
    result = _run(network.dnsdumpster_enum("example.com"))
    assert "error" not in result
    assert result["count"] == 0
    assert result["subdomains"] == []


def test_malformed_entries_dropped(monkeypatch):
    _stub(monkeypatch, subs=["a.example.com", 42, None, "  ", "b.example.com"])
    result = _run(network.dnsdumpster_enum("example.com"))
    assert result["subdomains"] == ["a.example.com", "b.example.com"]


def test_cap_at_1000(monkeypatch):
    _stub(monkeypatch, subs=[f"s{i}.example.com" for i in range(1500)])
    result = _run(network.dnsdumpster_enum("example.com"))
    assert result["count"] == 1000


def test_hosts_parser_from_documented_shape():
    data = {
        "a": [
            {"host": "www.example.com", "ips": [{"ip": "1.2.3.4"}]},
            {"host": "app.example.com", "ips": []},
            "not-a-dict",
            {"no_host_key": True},
        ],
        "cname": [{"host": "cdn.example.com"}],
        "mx": [{"host": "mail.example.com"}],
        "ns": [],
        "txt": ["v=spf1 -all"],  # no host field: ignored
    }
    hosts = network._dnsdumpster_hosts(data)
    assert hosts == [
        "www.example.com", "app.example.com",
        "cdn.example.com", "mail.example.com",
    ]


# ── findings adapter ─────────────────────────────────────────────
def test_adapter_sensitive_and_profile():
    result = {
        "target": "example.com", "count": 3,
        "subdomains": ["staging.example.com", "www.example.com",
                       "backup-2024.example.com"],
    }
    out = findings.extract_findings("dnsdumpster_enum", result, "example.com")
    assert [f.severity for f in out] == [
        findings.Severity.MEDIUM, findings.Severity.INFO,
    ]
    assert out[0].title == "Sensitive subdomain name: staging.example.com"
    assert out[0].confidence == 0.7
    assert out[1].evidence["count"] == 3


def test_adapter_no_sensitive_only_profile():
    result = {"target": "example.com", "count": 2,
              "subdomains": ["www.example.com", "mail.example.com"]}
    out = findings.extract_findings("dnsdumpster_enum", result, "example.com")
    assert len(out) == 1
    assert out[0].severity == findings.Severity.INFO


def test_adapter_caps_at_10():
    labels = ["staging", "backup", "qa", "git", "internal", "vpn",
              "sandbox", "demo", "debug", "tmp", "ci", "jenkins"]
    subs = [f"{lab}.example.com" for lab in labels]
    result = {"target": "example.com", "count": len(subs), "subdomains": subs}
    out = findings.extract_findings("dnsdumpster_enum", result, "example.com")
    assert len(out) == 10


def test_adapter_empty_and_error_no_finding():
    assert findings.extract_findings("dnsdumpster_enum", {}, "example.com") == []
    assert findings.extract_findings(
        "dnsdumpster_enum", {"target": "example.com", "error": "boom"},
        "example.com") == []
