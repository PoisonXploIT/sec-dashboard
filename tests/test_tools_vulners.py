"""OSINT backlog: vulners_search tool + findings adapter (no network)."""
import asyncio

import backend.findings as findings
import backend.tools.vuln as vuln


def _run(coro):
    return asyncio.run(coro)


def _stub(monkeypatch, rows=None, calls=None, key="K"):
    monkeypatch.setenv("VULNERS_API_KEY", "K")

    async def fake_query(term, advisory, limit, k):
        if calls is not None:
            calls.append((term, advisory, limit, k))
        return rows

    monkeypatch.setattr(vuln, "_vulners_query", fake_query)


# ── tool ────────────────────────────────────────────────────────
def test_empty_query_rejected():
    result = _run(vuln.vulners_search("  "))
    assert "No query" in result["error"]


def test_no_key_degrades_to_error_without_query(monkeypatch):
    monkeypatch.delenv("VULNERS_API_KEY", raising=False)
    calls = []

    async def fake_query(term, advisory, limit, k):
        calls.append((term, advisory, limit, k))
        return [{"id": "CVE-1999-0001"}]

    monkeypatch.setattr(vuln, "_vulners_query", fake_query)
    result = _run(vuln.vulners_search("Apache 2.4"))
    assert "VULNERS_API_KEY" in result["error"]
    assert calls == []  # no network attempt without a key


def test_cve_routing_uses_advisory_param(monkeypatch):
    calls = []
    _stub(monkeypatch, calls=calls, rows=[])
    result = _run(vuln.vulners_search("cve-2014-0160"))
    assert result["count"] == 0
    assert calls == [("CVE-2014-0160", True, 50, "K")]


def test_term_routing_uses_search_param(monkeypatch):
    calls = []
    _stub(monkeypatch, calls=calls, rows=[])
    result = _run(vuln.vulners_search("Apache HTTPd 2.4"))
    assert calls == [("Apache HTTPd 2.4", False, 50, "K")]


def test_query_failure_degrades_to_error(monkeypatch):
    _stub(monkeypatch, rows=None)
    result = _run(vuln.vulners_search("CVE-2014-0160"))
    assert result["error"] == "Vulners API unavailable or returned an error"


def test_success_maps_rows_sorts_and_caps(monkeypatch):
    rows = [
        {"id": "CVE-2020-0002", "title": "Second &amp; worse", "type": "cve",
         "severity": "HIGH", "description": "d" * 900, "published": "2020-01-02"},
        {"id": "CVE-2021-0001", "title": "First and worst", "type": "ghsa",
         "severity": "critical", "description": "desc", "published": "2021-05-01"},
        {"id": "CVE-2021-0001"},  # dup id: dropped (empty title too)
        {"no_id": True},          # malformed: dropped
    ]
    _stub(monkeypatch, rows=rows)
    result = _run(vuln.vulners_search("CVE-2021-0001"))
    assert result["count"] == 2
    ids = [v["id"] for v in result["vulns"]]
    assert ids == ["CVE-2021-0001", "CVE-2020-0002"]  # published desc
    first, second = result["vulns"]
    assert first["title"] == "First and worst"
    assert first["severity"] == "critical"
    assert first["url"] == "https://vulners.com/ghsa/CVE-2021-0001"
    assert len(second["description"]) == 500
    assert second["title"] == "Second & worse"


def test_max_results_clamped(monkeypatch):
    calls = []
    _stub(monkeypatch, calls=calls, rows=[])
    _run(vuln.vulners_search("x", max_results=9999))
    assert calls[0][2] == 100


# ── adapter ─────────────────────────────────────────────────────
def test_adapter_empty_result_no_findings():
    assert findings.extract_findings(
        "vulners_search", {"query": "x", "count": 0, "vulns": []}, "x") == []


def test_adapter_severity_mapping_and_dedup():
    vulns = [
        {"id": "CVE-2021-0001", "title": "Critical one", "type": "cve",
         "severity": "critical", "description": "d", "published": "2021-01-01",
         "url": "https://vulners.com/cve/CVE-2021-0001"},
        {"id": "CVE-2021-0001", "title": "dup"},          # dedup by id
        {"id": "CVE-2021-0002", "title": "Medium one", "severity": "medium"},
        {"id": "CVE-2021-0003", "title": "No severity"},
    ]
    out = findings.extract_findings(
        "vulners_search", {"query": "x", "count": 3, "vulns": vulns}, "x")
    by_id = {f.evidence["id"]: f for f in out}
    assert len(out) == 3
    assert by_id["CVE-2021-0001"].severity is findings.Severity.HIGH
    assert by_id["CVE-2021-0001"].confidence == 0.75
    assert by_id["CVE-2021-0002"].severity is findings.Severity.MEDIUM
    assert by_id["CVE-2021-0003"].severity is findings.Severity.LOW


def test_adapter_caps_at_10():
    vulns = [{"id": f"CVE-2021-{i:04d}", "title": f"t{i}",
             "severity": "high"} for i in range(20)]
    out = findings.extract_findings(
        "vulners_search", {"query": "x", "count": 20, "vulns": vulns}, "x")
    assert len(out) == 10


def test_adapter_ignores_error_result():
    out = findings.extract_findings(
        "vulners_search", {"query": "x", "error": "boom"}, "x")
    assert out == []
