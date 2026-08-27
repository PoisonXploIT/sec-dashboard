"""OSINT backlog: shodan_lookup extension + findings adapter (no network)."""
import asyncio

import backend.findings as findings
import backend.tools.osint as osint


def _run(coro):
    return asyncio.run(coro)


def _stub(monkeypatch, dsearch_data=None, host_data=None, calls=None):
    async def fake_query(ip, key):
        if calls is not None:
            calls.append(("dsearch", ip, key))
        return dsearch_data

    async def fake_host(ip, key):
        if calls is not None:
            calls.append(("host", ip, key))
        return host_data

    monkeypatch.setenv("SHODAN_API_KEY", "K")
    monkeypatch.setattr(osint, "_shodan_query", fake_query)
    monkeypatch.setattr(osint, "_shodan_host_query", fake_host)


# ── dsearch path (with key) ─────────────────────────────────────
def test_dsearch_parses_rows(monkeypatch):
    calls = []
    _stub(monkeypatch, dsearch_data={
        "total": 3,
        "result_set": [
            {
                "port": 80, "product": "nginx", "version": "1.25",
                "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n" * 10,
                "vulns": ["CVE-2021-23017"], "tags": ["web-server"],
                "cpe": "cpe:2.3:h:nginx", "os": "Linux",
                "hostnames": ["example.com"],
            },
            {
                "port": 22, "product": "OpenSSH", "version": "9.6",
                "banner": "SSH-2.0-OpenSSH_9.6", "vulns": [],
                "tags": ["ssh"], "os": "Linux", "hostnames": [],
            },
            "not-a-dict",  # malformed row is skipped
        ],
    }, calls=calls)

    result = _run(osint.shodan_lookup("1.2.3.4"))
    assert calls == [("dsearch", "1.2.3.4", "K")]  # no /host fallback
    assert result["source"] == "shodan_dsearch"
    assert result["total"] == 3
    assert result["count"] == 2
    top = result["results"][0]
    assert top["port"] == 80
    assert top["product"] == "nginx"
    assert top["vulns"] == ["CVE-2021-23017"]
    assert len(top["banner"]) <= 500  # banner truncated


def test_dsearch_empty_falls_back_to_host(monkeypatch):
    calls = []
    _stub(monkeypatch,
         dsearch_data={"total": 0, "result_set": []},
         host_data={
             "ports": [80], "vulns": [], "os": "Linux",
             "org": "Some Org", "isp": "Some ISP",
             "hostnames": ["h.example.com"],
             "data": [{"port": 80, "transport": "tcp",
                       "product": "nginx", "version": "1.25"}],
         },
         calls=calls)

    result = _run(osint.shodan_lookup("1.2.3.4"))
    assert [c[0] for c in calls] == ["dsearch", "host"]
    assert result["source"] == "shodan_api"
    assert result["services"][0]["product"] == "nginx"
    assert result["org"] == "Some Org"


def test_dsearch_failure_falls_back_to_host(monkeypatch):
    calls = []
    _stub(monkeypatch, dsearch_data=None,
         host_data={"ports": [], "data": []}, calls=calls)

    result = _run(osint.shodan_lookup("1.2.3.4"))
    assert [c[0] for c in calls] == ["dsearch", "host"]
    assert result["source"] == "shodan_api"


def test_both_fail_degrades_to_error(monkeypatch):
    _stub(monkeypatch, dsearch_data=None, host_data=None)
    result = _run(osint.shodan_lookup("1.2.3.4"))
    assert result["error"] == "No results"
    assert result["ip"] == "1.2.3.4"


def test_dsearch_malformed_vulns_dropped(monkeypatch):
    _stub(monkeypatch, dsearch_data={
        "total": 1,
        "result_set": [{
            "port": 8080, "product": "x", "version": "1",
            "banner": "b", "vulns": ["CVE-2020-0001", 42, None],
            "tags": [], "os": "", "hostnames": [],
        }],
    })
    result = _run(osint.shodan_lookup("1.2.3.4"))
    assert result["results"][0]["vulns"] == ["CVE-2020-0001"]


# ── findings adapter ─────────────────────────────────────────────
def test_adapter_dsearch_shape():
    result = {
        "source": "shodan_dsearch",
        "results": [
            {"port": 80, "product": "nginx", "version": "1.25",
             "banner": "Server: nginx/1.25", "vulns": ["CVE-2021-23017"],
             "tags": ["web-server"], "os": "Linux"},
            {"port": 3389, "product": "Microsoft Terminal Services",
             "version": "", "banner": "", "vulns": [],
             "tags": ["rdp"], "os": "Windows Server 2019"},
        ],
    }
    out = findings.extract_findings("shodan_lookup", result, "1.2.3.4")
    # Order: vuln first, then sensitive port, then profile INFO.
    assert [f.severity for f in out] == [
        findings.Severity.HIGH, findings.Severity.MEDIUM,
        findings.Severity.INFO,
    ]
    v = out[0]
    assert v.cve == "CVE-2021-23017"
    assert v.confidence == 0.75
    assert v.category == "Vulnerability"
    assert "nginx 1.25 (port 80)" in v.title
    assert v.evidence["banner"] == "Server: nginx/1.25"
    assert out[1].title == "RDP exposed"
    assert out[1].evidence["port"] == 3389
    assert out[2].severity == findings.Severity.INFO
    # os/tags come from the first row that carries them
    assert out[2].evidence["os"] == "Linux"


def test_adapter_host_shape_ports_only():
    result = {
        "source": "shodan_api",
        "os": "Linux",
        "services": [
            {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "9.6"},
            {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.25"},
        ],
    }
    out = findings.extract_findings("shodan_lookup", result, "1.2.3.4")
    # Only the sensitive port is reported; 80 is not in the map.
    assert [f.severity for f in out] == [findings.Severity.MEDIUM, findings.Severity.INFO]
    assert out[0].title == "SSH exposed"
    assert out[1].evidence["os"] == "Linux"


def test_adapter_internetdb_shape():
    result = {
        "source": "shodan_internetdb",
        "ports": [22, 3389],
        "vulns": ["CVE-2014-0160", "CVE-2014-0160"],  # deduped
        "os": "Windows Server 2019",
        "tags": ["rdp", "windows"],
    }
    out = findings.extract_findings("shodan_lookup", result, "1.2.3.4")
    assert [f.severity for f in out] == [
        findings.Severity.HIGH,
        findings.Severity.MEDIUM, findings.Severity.MEDIUM,
        findings.Severity.INFO,
    ]
    assert out[0].cve == "CVE-2014-0160"
    assert out[0].title == "Known vulnerability CVE-2014-0160"  # no port ctx
    assert [f.title for f in out[1:3]] == ["SSH exposed", "RDP exposed"]


def test_adapter_caps_at_10():
    result = {
        "source": "shodan_dsearch",
        "results": [
            {"port": None, "product": "", "version": "", "banner": "",
             "vulns": [f"CVE-2020-{i:04d}"], "tags": [], "os": ""}
            for i in range(15)
        ],
    }
    out = findings.extract_findings("shodan_lookup", result, "1.2.3.4")
    assert len(out) == 10
    assert all(f.severity == findings.Severity.HIGH for f in out)


def test_adapter_empty_result_no_finding():
    assert findings.extract_findings("shodan_lookup", {}, "1.2.3.4") == []
    assert findings.extract_findings(
        "shodan_lookup", {"source": "shodan_dsearch", "results": []},
        "1.2.3.4") == []
