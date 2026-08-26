"""Unified finding model for sec-dashboard.

Every tool keeps returning its existing human-readable JSON (the UI is
untouched). On top of that, each tool result can be translated into a list
of normalized ``Finding`` objects with severity, evidence, confidence and
remediation. This is the base for:

- target scoring (0-100)
- Splunk export with a stable sourcetype schema
- executive PDF reports
- historical comparison between scans
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Weights used by score_findings(). INFO contributes 0.
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    """One normalized security finding produced by a tool."""

    tool: str
    category: str
    severity: Severity
    title: str
    description: str = ""
    evidence: dict | None = None
    cve: str | None = None
    confidence: float = 1.0          # 0.0 - 1.0
    remediation: str = ""
    target: str = ""
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ── Adapters: tool result -> list[Finding] ─────────────────────
ADAPTERS: dict[str, object] = {}


def register(*tool_ids: str):
    """Decorator: register a findings adapter for one or more tool ids."""
    def deco(fn):
        for tid in tool_ids:
            ADAPTERS[tid] = fn
        return fn
    return deco


@register("header_analyzer")
def _adapt_header_analyzer(result: dict, target: str) -> list[Finding]:
    out: list[Finding] = []
    url = result.get("url", "")
    for hdr in result.get("security_headers_missing", []):
        name = hdr.get("header", "")
        # HSTS absence is the most impactful one; others are lower risk.
        sev = Severity.MEDIUM if "Strict-Transport" in name else Severity.LOW
        out.append(Finding(
            tool="header_analyzer", category="Web Security", severity=sev,
            title=f"Missing security header: {name}",
            description=hdr.get("description", ""),
            evidence={"url": url, "header": name},
            remediation=hdr.get("recommendation", f"Add the {name} response header."),
            target=target, confidence=0.9,
        ))
    for leak in result.get("information_leakage", []):
        out.append(Finding(
            tool="header_analyzer", category="Web Security", severity=Severity.LOW,
            title=f"Information leakage via header: {leak.get('header', '')}",
            description=leak.get("risk", ""),
            evidence={"url": url, "header": leak.get("header"), "value": leak.get("value")},
            remediation="Remove or minimize the header value.",
            target=target, confidence=0.8,
        ))
    return out


@register("ssl_analyzer")
def _adapt_ssl_analyzer(result: dict, target: str) -> list[Finding]:
    out: list[Finding] = []
    tls = result.get("tls_version", "")
    cipher = result.get("cipher_suite", "") or ""
    if tls and any(old in tls for old in ("TLSv1/", "TLSv1 ", "SSL")):
        sev = Severity.CRITICAL if "SSL" in tls else Severity.HIGH
        out.append(Finding(
            tool="ssl_analyzer", category="Network Recon", severity=sev,
            title=f"Deprecated TLS version negotiated: {tls}",
            evidence={"tls_version": tls, "cipher_suite": cipher},
            remediation="Disable legacy TLS; require TLS 1.2+ on the server.",
            target=target, confidence=0.95,
        ))
    weak_ciphers = ("RC4", "DES_", "3DES", "NULL", "eNULL", "anon")
    if any(w in cipher for w in weak_ciphers):
        out.append(Finding(
            tool="ssl_analyzer", category="Network Recon", severity=Severity.HIGH,
            title=f"Weak cipher suite negotiated: {cipher}",
            evidence={"tls_version": tls, "cipher_suite": cipher},
            remediation="Restrict the server to strong AEAD ciphers (AES-GCM / ChaCha20).",
            target=target, confidence=0.9,
        ))
    if not result.get("valid"):
        out.append(Finding(
            tool="ssl_analyzer", category="Network Recon", severity=Severity.MEDIUM,
            title="Certificate validation failed",
            description=result.get("error", ""),
            evidence={"host": result.get("host"), "port": result.get("port")},
            remediation="Fix the certificate chain or validity period.",
            target=target, confidence=0.8,
        ))
    return out


@register("port_scanner")
def _adapt_port_scanner(result: dict, target: str) -> list[Finding]:
    out: list[Finding] = []
    for p in result.get("open_ports", []):
        port = p.get("port")
        service = p.get("service", "")
        # Exposed management/admin ports are the notable ones.
        sensitive = {
            22: ("SSH exposed", "Restrict with key-only auth, fail2ban or VPN."),
            3389: ("RDP exposed", "Remove RDP from internet-facing hosts; use VPN."),
            3306: ("MySQL exposed", "Bind MySQL to localhost or put it behind the firewall."),
            5432: ("PostgreSQL exposed", "Bind PostgreSQL to localhost or put it behind the firewall."),
            27017: ("MongoDB exposed", "Disable unauthenticated remote access; require auth."),
            6379: ("Redis exposed", "Do not expose Redis without auth; bind to internal networks."),
            8080: ("HTTP alternate port", "Review what service runs here and whether it is needed."),
        }
        if port in sensitive:
            title, rem = sensitive[port]
            out.append(Finding(
                tool="port_scanner", category="Network Recon", severity=Severity.MEDIUM,
                title=title, description=f"Port {port}/{p.get('state', 'open')} — service: {service}",
                evidence={"port": port, "state": p.get("state"), "service": service},
                remediation=rem, target=target, confidence=0.9,
            ))
    return out


@register("cors_checker")
def _adapt_cors_checker(result: dict, target: str) -> list[Finding]:
    if not result.get("vulnerable"):
        return []
    out = []
    for f in result.get("findings", []):
        out.append(Finding(
            tool="cors_checker", category="Web Security", severity=Severity.MEDIUM,
            title=f"CORS misconfiguration: {f.get('name', '')}",
            description=f.get("description", ""),
            evidence={"url": result.get("url"), "test": f},
            remediation="Validate Origin server-side and avoid null/wildcard in Access-Control-Allow-Origin.",
            target=target, confidence=0.85,
        ))
    return out


@register("sqli_scanner", "xss_scanner")
def _adapt_injection(result: dict, target: str) -> list[Finding]:
    if not result.get("findings"):
        return []
    out = []
    for f in result.get("findings", []):
        out.append(Finding(
            tool="injection_scanner", category="Web Security", severity=Severity.HIGH,
            title=f"Injection finding on parameter: {f.get('param', '')}",
            description=f.get("type", ""),
            evidence={"url": result.get("url"), "param": f.get("param"), "type": f.get("type")},
            remediation="Use parameterized queries / output encoding and a WAF rule.",
            target=target, confidence=0.7,
        ))
    return out


@register("open_redirect")
def _adapt_open_redirect(result: dict, target: str) -> list[Finding]:
    if not result.get("vulnerable"):
        return []
    out = []
    for f in result.get("findings", []):
        out.append(Finding(
            tool="open_redirect", category="Web Security", severity=Severity.MEDIUM,
            title=f"Open redirect via parameter: {f.get('param', '')}",
            description=f.get("url", ""),
            evidence={"url": result.get("url"), "param": f.get("param")},
            remediation="Whitelist allowed redirect targets; validate scheme and host.",
            target=target, confidence=0.8,
        ))
    return out


@register("cve_search")
def _adapt_cve_search(result: dict, target: str) -> list[Finding]:
    sev_map = {
        "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
    }
    out = []
    for cve in result.get("cves", []):
        sev = sev_map.get(str(cve.get("severity", "")).upper(), Severity.INFO)
        out.append(Finding(
            tool="cve_search", category="Vulnerability", severity=sev,
            title=f"{cve.get('id', '')} (CVSS {cve.get('cvss_score', '?')})",
            description=cve.get("description", ""),
            evidence={"published": cve.get("published"), "cvss_score": cve.get("cvss_score")},
            cve=cve.get("id"),
            remediation="Check whether the affected version is deployed and patch.",
            target=target, confidence=0.9,
        ))
    return out


@register("cve_correlation")
def _adapt_cve_correlation(result: dict, target: str) -> list[Finding]:
    """KEV hits are CRITICAL; NVD critical/high CVEs on the live stack HIGH.

    Lower severities are intentionally dropped to keep the score meaningful:
    a WordPress install has hundreds of historical CVEs and only the ones
    actively exploited (KEV) or still critical matter for a recon report.
    """
    sev_map = {
        "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
    }
    out: list[Finding] = []
    for m in result.get("kev_matches", []):
        out.append(Finding(
            tool="cve_correlation", category="Vulnerability",
            severity=Severity.CRITICAL,
            title=f"Known exploited vulnerability: {m.get('id', '')}",
            description=m.get("vulnerability_name", ""),
            evidence={"tech": m.get("tech"), "due_date": m.get("due_date")},
            cve=m.get("id"),
            remediation="Patch immediately: CISA lists this as actively exploited.",
            target=target, confidence=0.95,
        ))
    kev_ids = {m.get("id") for m in result.get("kev_matches", [])}
    emitted = 0
    for cve in result.get("cves", []):
        if emitted >= 10:
            break
        cid = cve.get("id")
        if cid in kev_ids:  # already covered by the KEV finding above
            continue
        sev_str = str(cve.get("severity") or "").upper()
        if sev_str not in ("CRITICAL", "HIGH"):
            continue
        emitted += 1
        out.append(Finding(
            tool="cve_correlation", category="Vulnerability",
            severity=Severity.HIGH,
            title=f"{cid} on {cve.get('tech', '')} (CVSS {cve.get('cvss_score', '?')})",
            description=cve.get("description", ""),
            evidence={"tech": cve.get("tech"), "cvss_score": cve.get("cvss_score")},
            cve=cid,
            remediation="Verify the deployed version is affected and patch.",
            target=target, confidence=0.8,
        ))
    return out


@register("subdomain_takeover")
def _adapt_subdomain_takeover(result: dict, target: str) -> list[Finding]:
    """Every dangling CNAME is CRITICAL: the resource is claimable now."""
    out: list[Finding] = []
    seen: set[str] = set()
    for t in result.get("takeovers", []):
        sub = t.get("sub") or ""
        if not sub or sub in seen:
            continue
        seen.add(sub)
        out.append(Finding(
            tool="subdomain_takeover", category="Vulnerability",
            severity=Severity.CRITICAL,
            title=f"Subdomain takeover: {sub} -> {t.get('cname', '')}",
            description=(
                f"Dangling CNAME pointing at {t.get('platform', '')}: the "
                "upstream resource is unclaimed and an attacker can take over "
                "this subdomain."
            ),
            evidence={"cname": t.get("cname"), "platform": t.get("platform")},
            remediation="Reclaim the resource on the platform or remove the DNS record.",
            target=target, confidence=0.95,
        ))
    return out[:20]


@register("secret_leak_scan")
def _adapt_secret_leak_scan(result: dict, target: str) -> list[Finding]:
    """Severity by tier: exposed .git/ is CRITICAL, platform keys HIGH.

    Dedup key = source + type + redacted evidence, so the same secret found
    in two files stays separate but one file with two matches of a type
    (first-match-wins in the handler) never duplicates.
    """
    out: list[Finding] = []
    seen: set[str] = set()
    for p in result.get("git_exposed_paths", []):
        key = f"{p}|git|"
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(
            tool="secret_leak_scan", category="Web Security",
            severity=Severity.CRITICAL,
            title=f"Exposed .git repository object: {p}",
            description=(
                "The target serves Git metadata, which can leak the full source "
                "history including previously committed credentials."
            ),
            evidence={"path": p},
            remediation="Remove public access to /.git/ (server rule) and rotate any secrets that were ever committed.",
            target=target, confidence=0.95,
        ))
    for f in result.get("findings", []):
        key = f"{f.get('source', '')}|{f.get('type', '')}|{f.get('evidence', '')}"
        if key in seen:
            continue
        seen.add(key)
        tier = f.get("tier", "")
        sev = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}.get(tier, Severity.MEDIUM)
        out.append(Finding(
            tool="secret_leak_scan", category="Web Security",
            severity=sev,
            title=f"Potential secret exposed ({f.get('type', '')}) in {f.get('source', '')}",
            description=f"High-confidence pattern match ({tier} tier) in served content.",
            evidence={"source": f.get("source"), "type": f.get("type"), "match": f.get("evidence")},
            remediation="Revoke/rotate the exposed credential and remove it from the served file or repository.",
            target=target, confidence=0.9,
        ))
    return out[:20]


@register("tech_detector")
def _adapt_tech_detector(result: dict, target: str) -> list[Finding]:
    """Informational only: detected stack feeds later CVE correlation."""
    techs: dict = result.get("technologies", {})
    if not techs:
        return []
    flat = [t for cat in techs.values() for t in (cat if isinstance(cat, list) else [cat])]
    return [Finding(
        tool="tech_detector", category="Web Security", severity=Severity.INFO,
        title=f"Stack fingerprint: {len(flat)} technologies",
        evidence={"technologies": techs, "url": result.get("url")},
        remediation="", target=target, confidence=0.8,
    )]


def extract_findings(tool: str, result: dict, target: str = "") -> list[Finding]:
    """Translate a tool result into normalized findings.

    Unknown tools fall back to a single INFO finding so downstream consumers
    (scoring, Splunk) always get something for every completed scan.
    """
    adapter = ADAPTERS.get(tool)
    if adapter is not None:
        try:
            return adapter(result, target)
        except Exception:
            # Adapter bugs must never break the scan pipeline.
            return _fallback_findings(tool, result, target)
    return _fallback_findings(tool, result, target)


def _fallback_findings(tool: str, result: dict, target: str) -> list[Finding]:
    if not result or "error" in result:
        return []
    return [Finding(
        tool=tool, category="Uncategorized", severity=Severity.INFO,
        title=f"{tool} completed (no dedicated adapter)",
        evidence={}, target=target, confidence=0.5,
    )]


def score_findings(findings: list[Finding]) -> int:
    """Aggregate findings into a 0-100 risk score for a target.

    Weighted sum of severities scaled by confidence, capped at 100.
    INFO findings do not contribute to the score.
    """
    total = 0.0
    for f in findings:
        w = SEVERITY_WEIGHT.get(f.severity, 0)
        total += w * max(0.0, min(1.0, f.confidence))
    return int(min(100, round(total)))


def score_finding_dicts(findings: list[dict]) -> int:
    """Same as score_findings but for serialized findings (dicts).

    Used to aggregate per-tool findings already turned into dicts by the
    scanner/pipeline (e.g. pipeline-level totals after Fase 0.4).
    """
    weight_by_value = {sev.value: w for sev, w in SEVERITY_WEIGHT.items()}
    total = 0.0
    for f in findings:
        w = weight_by_value.get(f.get("severity", "info"), 0)
        try:
            conf = float(f.get("confidence", 1.0))
        except (TypeError, ValueError):
            conf = 0.0
        total += w * max(0.0, min(1.0, conf))
    return int(min(100, round(total)))
