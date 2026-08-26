"""F1-CVE: cve_correlation tool + findings adapter (no network)."""
import asyncio

import backend.findings as findings
import backend.tools.web as web


# ── _extract_versions ───────────────────────────────────────────
def test_extract_versions_parses_server_header():
    assert web._extract_versions("nginx/1.25.3") == {"nginx": "1.25.3"}


def test_extract_versions_multiple_and_unknown():
    v = web._extract_versions("Apache/2.4.58 (Ubuntu)")
    assert v.get("Apache") == "2.4.58"


def test_extract_versions_empty_header():
    assert web._extract_versions("") == {}
    assert web._extract_versions(None) == {}


# ── cve_correlation handler (stubbed sources) ────────────────────
def _run(coro):
    return asyncio.run(coro)


def test_cve_correlation_flags_kev_and_extracts_versions(monkeypatch):
    async def fake_tech_detector(url, **kw):
        return {
            "url": "https://example.com",
            "status": 200,
            "server": "nginx/1.25.3",
            "technologies": {"CMS": ["WordPress"], "Servers": ["nginx"]},
        }

    async def fake_nvd(term):
        if term == "wordpress":
            return [{
                "id": "CVE-2026-1111",
                "description": "Critical flaw in WordPress core",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "published": "2026-01-01T00:00:00.000",
            }]
        return []

    async def fake_kev():
        return [{
            "cveID": "CVE-2026-1111",
            "vulnerability_name": "WordPress before 6.5 - critical flaw",
            "dueDate": "2026-02-01T00:00:00.000",
            "requiredAction": "Patch to latest version.",
        }]

    monkeypatch.setattr(web, "tech_detector", fake_tech_detector)
    monkeypatch.setattr(web, "_nvd_product_search", fake_nvd)
    monkeypatch.setattr(web, "_fetch_kev", fake_kev)

    result = _run(web.cve_correlation("example.com"))

    assert result["versions"] == {"nginx": "1.25.3"}
    assert result["count"] == 1
    cve = result["cves"][0]
    assert cve["in_kev"] is True
    assert cve["tech"] == "wordpress"
    # KEV CVE must sort first
    assert result["cves"][0]["id"] == "CVE-2026-1111"
    assert len(result["kev_matches"]) == 1
    assert result["kev_matches"][0]["id"] == "CVE-2026-1111"


def test_cve_correlation_propagates_tech_detector_error(monkeypatch):
    async def fake_tech_detector(url, **kw):
        return {"url": url, "error": "boom"}

    monkeypatch.setattr(web, "tech_detector", fake_tech_detector)
    result = _run(web.cve_correlation("example.com"))
    assert result.get("error") == "boom"


def test_cve_correlation_no_technologies(monkeypatch):
    async def fake_tech_detector(url, **kw):
        return {"url": "https://x", "status": 200, "server": "", "technologies": {}}

    async def fake_nvd(term):
        return []

    async def fake_kev():
        return []

    monkeypatch.setattr(web, "tech_detector", fake_tech_detector)
    monkeypatch.setattr(web, "_nvd_product_search", fake_nvd)
    monkeypatch.setattr(web, "_fetch_kev", fake_kev)

    result = _run(web.cve_correlation("example.com"))
    assert result["count"] == 0
    assert result["cves"] == []
    assert result["kev_matches"] == []


# ── findings adapter ─────────────────────────────────────────────
def test_adapter_kev_is_critical_with_cve_field():
    result = {
        "kev_matches": [{
            "tech": "wordpress",
            "id": "CVE-2026-1111",
            "vulnerability_name": "WordPress critical flaw",
            "due_date": "2026-02-01T00:00:00.000",
        }],
        "cves": [{
            "tech": "wordpress", "id": "CVE-2026-1111",
            "description": "d", "cvss_score": 9.8, "severity": "CRITICAL",
            "in_kev": True,
        }],
    }
    out = findings.extract_findings("cve_correlation", result, "example.com")
    assert len(out) == 1  # KEV finding only; the CVE is deduped by id
    f = out[0]
    assert f.severity == findings.Severity.CRITICAL
    assert f.cve == "CVE-2026-1111"


def test_adapter_emits_high_sev_cves_and_skips_lower():
    result = {
        "kev_matches": [],
        "cves": [
            {"tech": "apache", "id": "CVE-2026-2222", "description": "a",
             "cvss_score": 9.1, "severity": "CRITICAL", "in_kev": False},
            {"tech": "nginx", "id": "CVE-2026-3333", "description": "b",
             "cvss_score": 7.4, "severity": "HIGH", "in_kev": False},
            {"tech": "php", "id": "CVE-2026-4444", "description": "c",
             "cvss_score": 5.9, "severity": "MEDIUM", "in_kev": False},
        ],
    }
    out = findings.extract_findings("cve_correlation", result, "example.com")
    ids = [f.cve for f in out]
    assert "CVE-2026-4444" not in ids  # MEDIUM dropped on purpose
    assert set(ids) == {"CVE-2026-2222", "CVE-2026-3333"}
    assert all(f.severity == findings.Severity.HIGH for f in out)


def test_adapter_empty_result():
    assert findings.extract_findings("cve_correlation", {}, "example.com") == []
