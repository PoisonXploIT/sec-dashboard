"""Tests for the unified finding model (backend/findings.py)."""
import json

from backend.findings import (
    ADAPTERS,
    SEVERITY_WEIGHT,
    Finding,
    Severity,
    extract_findings,
    score_findings,
)


def test_finding_serialization_roundtrip():
    f = Finding(
        tool="header_analyzer", category="Web Security",
        severity=Severity.HIGH, title="t", evidence={"a": 1},
        cve="CVE-2024-1234", confidence=0.9, target="example.com",
    )
    d = f.to_dict()
    assert d["severity"] == "high"
    # Must be JSON-serializable for Splunk / API consumers.
    json.dumps(d)
    assert d["tool"] == "header_analyzer"
    assert d["evidence"] == {"a": 1}


def test_severity_weights_ordered():
    w = {s.value: v for s, v in SEVERITY_WEIGHT.items()}
    assert w["critical"] > w["high"] > w["medium"] > w["low"] >= w["info"]


def test_header_analyzer_adapter_missing_hsts():
    result = {
        "url": "https://example.com",
        "security_headers_missing": [
            {"header": "Strict-Transport-Security", "description": "no HSTS"},
            {"header": "X-Content-Type-Options", "description": "missing"},
        ],
        "information_leakage": [{"header": "Server", "value": "nginx/1.25", "risk": "version leak"}],
    }
    findings = extract_findings("header_analyzer", result, "example.com")
    sevs = {f.severity for f in findings}
    assert Severity.MEDIUM in sevs  # HSTS missing
    assert len(findings) == 3


def test_ssl_analyzer_adapter_legacy_tls():
    result = {"tls_version": "TLSv1/SSLv3", "cipher_suite": "AES128-SHA", "valid": True}
    findings = extract_findings("ssl_analyzer", result, "example.com")
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_ssl_analyzer_adapter_weak_cipher():
    result = {"tls_version": "TLSv1.2", "cipher_suite": "RC4-SHA", "valid": True}
    findings = extract_findings("ssl_analyzer", result, "example.com")
    assert any(f.severity == Severity.HIGH and "cipher" in f.title.lower() for f in findings)


def test_port_scanner_adapter_sensitive_ports_only():
    result = {
        "open_ports": [
            {"port": 80, "state": "open", "service": "http"},
            {"port": 27017, "state": "open", "service": "mongodb"},
        ]
    }
    findings = extract_findings("port_scanner", result, "example.com")
    assert len(findings) == 1
    assert "MongoDB" in findings[0].title


def test_injection_adapter_empty_when_clean():
    assert extract_findings("sqli_scanner", {"url": "https://x", "findings": []}, "x") == []


def test_cve_search_adapter_maps_severity():
    result = {"cves": [
        {"id": "CVE-2024-1000", "severity": "HIGH", "cvss_score": 8.1, "description": "d"},
        {"id": "CVE-2024-1001", "severity": "CRITICAL", "cvss_score": 9.8, "description": "d"},
    ]}
    findings = extract_findings("cve_search", result, "")
    assert {f.severity for f in findings} == {Severity.HIGH, Severity.CRITICAL}
    assert all(f.cve for f in findings)


def test_fallback_for_unregistered_tool():
    findings = extract_findings("some_future_tool", {"whatever": 1}, "t")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


def test_fallback_ignores_error_results():
    assert extract_findings("some_future_tool", {"error": "boom"}, "t") == []


def test_adapter_crash_never_raises(monkeypatch):
    def bad(result, target):
        raise RuntimeError("adapter bug")

    monkeypatch.setitem(ADAPTERS, "broken_tool", bad)
    findings = extract_findings("broken_tool", {"ok": True}, "t")
    assert len(findings) == 1  # falls back to INFO finding


def test_score_bounds_and_monotonicity():
    info = [Finding(tool="t", category="c", severity=Severity.INFO, title="i")]
    assert score_findings(info) == 0

    low = [Finding(tool="t", category="c", severity=Severity.LOW, title="l")]
    high = [Finding(tool="t", category="c", severity=Severity.HIGH, title="h")]
    crit = [Finding(tool="t", category="c", severity=Severity.CRITICAL, title="c")]
    assert 0 < score_findings(low) < score_findings(high) < score_findings(crit)

    # Confidence scales the contribution down.
    f_low_conf = Finding(tool="t", category="c", severity=Severity.CRITICAL,
                         title="c", confidence=0.1)
    assert score_findings([f_low_conf]) < score_findings(crit)

    # Cap at 100.
    many = [Finding(tool="t", category="c", severity=Severity.CRITICAL, title="x") for _ in range(50)]
    assert score_findings(many) == 100
