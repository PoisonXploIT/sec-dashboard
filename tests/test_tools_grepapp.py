"""OSINT backlog: grepapp_search tool + findings adapter (no network)."""
import asyncio

import backend.findings as findings
import backend.tools.osint as osint


def _run(coro):
    return asyncio.run(coro)


def _stub(monkeypatch, data=None):
    async def fake_query(query):
        return data

    monkeypatch.setattr(osint, "_grepapp_query", fake_query)


def _body(hits=None, total=0, buckets=None):
    return {
        "time": 12,
        "facets": {"lang": {"buckets": buckets or []}},
        "hits": {"total": total, "hits": hits if hits is not None else []},
    }


# ── tool ────────────────────────────────────────────────────────
def test_empty_query_rejected():
    result = _run(osint.grepapp_search("   "))
    assert "No query" in result["error"]


def test_query_failure_degrades_to_error(monkeypatch):
    _stub(monkeypatch, data=None)
    result = _run(osint.grepapp_search("sammideblas.com"))
    assert result["error"] == "grep.app search unavailable or returned an error"


def test_malformed_body_degrades_to_empty(monkeypatch):
    # Shape validation lives in _grepapp_query (returns None); a body that
    # still reaches the handler degrades to an empty inventory, not an error.
    _stub(monkeypatch, data={"hits": "nope"})
    result = _run(osint.grepapp_search("sammideblas.com"))
    assert "error" not in result
    assert result["count"] == 0 and result["repos"] == []


def test_success_maps_rows_dedupes_and_keeps_facets(monkeypatch):
    hits = [
        {"repo": "Acme/Repo", "path": "config/prod.yaml", "branch": "main",
         "total_matches": 3},
        {"repo": "acme/repo", "path": "Config/Prod.YAML"},  # dup after normalize
        {"path": "no-repo.txt"},                            # malformed: dropped
        "garbage",                                          # not a dict: dropped
        {"repo": "Other/Creds", "path": ".env", "total_matches": 1},
    ]
    _stub(monkeypatch, data=_body(hits=hits, total=42,
                                  buckets=[{"val": "Python", "count": 5},
                                           {"val": "YAML", "count": 2}]))
    result = _run(osint.grepapp_search("sammideblas.com"))
    assert "error" not in result
    assert result["count"] == 2
    assert result["total"] == 42
    assert [r["repo"] for r in result["repos"]] == ["Acme/Repo", "Other/Creds"]
    assert result["repos"][0]["path"] == "config/prod.yaml"
    assert result["languages"] == [{"lang": "Python", "count": 5},
                                   {"lang": "YAML", "count": 2}]


def test_max_results_clamped(monkeypatch):
    hits = [{"repo": f"o/r{i}", "path": f"f{i}"} for i in range(10)]
    _stub(monkeypatch, data=_body(hits=hits))
    result = _run(osint.grepapp_search("x", max_results=3))
    assert result["count"] == 3
    result = _run(osint.grepapp_search("x", max_results=9999))
    assert result["count"] == 10


def test_zero_hits_clean(monkeypatch):
    _stub(monkeypatch, data=_body())
    result = _run(osint.grepapp_search("sammideblas.com"))
    assert result["count"] == 0 and result["repos"] == []


# ── adapter ─────────────────────────────────────────────────────
def test_adapter_empty_result_no_findings():
    assert findings.extract_findings(
        "grepapp_search", {"query": "x", "count": 0, "repos": []}, "x") == []


def test_adapter_sensitive_path_medium_and_profile():
    result = {
        "query": "sammideblas.com", "count": 2, "total": 42,
        "repos": [
            {"repo": "a/b", "path": ".env", "branch": "main", "total_matches": 1},
            {"repo": "c/d", "path": "README.md", "branch": "main"},
        ],
        "languages": [{"lang": "Python", "count": 1}],
    }
    out = findings.extract_findings("grepapp_search", result, "sammideblas.com")
    sevs = [f.severity for f in out]
    assert len(out) == 2
    med = next(f for f in out if f.severity is findings.Severity.MEDIUM)
    assert "a/b:.env" in med.title and med.confidence == 0.7
    info = next(f for f in out if f.severity is findings.Severity.INFO)
    assert info.evidence["count"] == 2


def test_adapter_only_profile_when_no_sensitive_paths():
    result = {
        "query": "x", "count": 1, "total": 1,
        "repos": [{"repo": "a/b", "path": "src/main.py"}],
        "languages": [],
    }
    out = findings.extract_findings("grepapp_search", result, "x")
    assert len(out) == 1
    assert out[0].severity is findings.Severity.INFO


def test_adapter_caps_at_10():
    repos = [{"repo": f"o/{i}", "path": ".env"} for i in range(20)]
    result = {"query": "x", "count": 20, "total": 20, "repos": repos}
    out = findings.extract_findings("grepapp_search", result, "x")
    assert len(out) == 10


def test_adapter_ignores_error_result():
    out = findings.extract_findings(
        "grepapp_search", {"query": "x", "error": "boom"}, "x")
    assert out == []
