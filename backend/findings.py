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

import hashlib
import time
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
    finding_id: str = ""
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        # Stable identity across runs: the same tool+category+severity+title
        # hashes to the same id, so historical comparison (new/fixed/persistent)
        # can match findings between scans. Adapters may pass an explicit
        # finding_id when they know a better natural key.
        if not self.finding_id:
            raw = "|".join((self.tool, self.category, self.severity.value, self.title))
            self.finding_id = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]

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


@register("ssl_deep_analyzer")
def _adapt_ssl_deep_analyzer(result: dict, target: str) -> list[Finding]:
    checks = result.get("checks") or []
    if not checks:
        return []
    # (check id, status) -> severity. Only the listed pairs are reported:
    # protocol/cipher problems on fail, hygiene items on their own status.
    severity_by_id = {
        ("tls_legacy", "fail"): Severity.HIGH,
        ("weak_cipher", "fail"): Severity.HIGH,
        ("cert_expired", "fail"): Severity.HIGH,
        ("self_signed", "fail"): Severity.MEDIUM,
        ("no_forward_secrecy", "fail"): Severity.MEDIUM,
        ("hsts_missing", "fail"): Severity.MEDIUM,
        ("hsts_short", "fail"): Severity.LOW,
        ("cert_expiring", "warn"): Severity.LOW,
        ("ocsp_unavailable", "warn"): Severity.LOW,
    }
    remediation = {
        "tls_legacy": "Disable TLS 1.0/1.1; require TLS 1.2+ on the server.",
        "weak_cipher": "Restrict the server to strong AEAD ciphers (AES-GCM / ChaCha20).",
        "cert_expired": "Renew the certificate and fix the automation that keeps it valid.",
        "self_signed": "Replace the self-signed certificate with a CA-issued one.",
        "no_forward_secrecy": "Enable ECDHE/DHE cipher suites for forward secrecy.",
        "hsts_missing": "Add a Strict-Transport-Security header (max-age >= 180 days).",
        "hsts_short": "Raise HSTS max-age to at least 180 days (consider preload).",
        "cert_expiring": "Renew the certificate before it expires.",
        "ocsp_unavailable": "Enable OCSP stapling or publish a reachable OCSP responder.",
    }
    out: list[Finding] = []
    grade = result.get("grade")
    for chk in checks:
        cid, status = chk.get("id"), chk.get("status")
        sev = severity_by_id.get((cid, status))
        if sev is None:
            continue
        out.append(Finding(
            tool="ssl_deep_analyzer", category="Network Recon",
            severity=sev,
            title=f"{chk.get('detail') or cid} (grade {grade})" if grade else cid,
            evidence={"check": cid, "status": status,
                      "detail": chk.get("detail"), "grade": grade},
            remediation=remediation.get(cid, ""),
            target=target, confidence=0.9,
        ))
        if len(out) >= 10:
            break
    return out


# Exposed management/admin ports worth reporting (shared by the
# port_scanner and shodan_lookup adapters).
_SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    22: ("SSH exposed", "Restrict with key-only auth, fail2ban or VPN."),
    3389: ("RDP exposed", "Remove RDP from internet-facing hosts; use VPN."),
    3306: ("MySQL exposed", "Bind MySQL to localhost or put it behind the firewall."),
    5432: ("PostgreSQL exposed", "Bind PostgreSQL to localhost or put it behind the firewall."),
    27017: ("MongoDB exposed", "Disable unauthenticated remote access; require auth."),
    6379: ("Redis exposed", "Do not expose Redis without auth; bind to internal networks."),
    8080: ("HTTP alternate port", "Review what service runs here and whether it is needed."),
}


@register("port_scanner")
def _adapt_port_scanner(result: dict, target: str) -> list[Finding]:
    out: list[Finding] = []
    for p in result.get("open_ports", []):
        port = p.get("port")
        service = p.get("service", "")
        # Exposed management/admin ports are the notable ones.
        info = _SENSITIVE_PORTS.get(port)
        if info is None:
            continue
        title, rem = info
        out.append(Finding(
            tool="port_scanner", category="Network Recon", severity=Severity.MEDIUM,
            title=title, description=f"Port {port}/{p.get('state', 'open')} — service: {service}",
            evidence={"port": port, "state": p.get("state"), "service": service},
            remediation=rem, target=target, confidence=0.9,
        ))
    return out


@register("shodan_lookup")
def _adapt_shodan_lookup(result: dict, target: str) -> list[Finding]:
    """Shodan-attested weaknesses on the IP.

    Vuln ids come from Shodan's banner matching (no deployment confirmation
    beyond the banner itself), so they are HIGH at confidence 0.75;
    sensitive exposed ports MEDIUM; os/tags profile INFO. Cap 10.
    """
    rows = [r for r in result.get("results") or [] if isinstance(r, dict)]
    top_vulns = [str(v) for v in result.get("vulns") or [] if isinstance(v, str)]

    vuln_ctx: list[tuple[str, dict]] = []
    ports: set[int] = set()
    if rows:
        for r in rows:
            port = r.get("port")
            if isinstance(port, int):
                ports.add(port)
            svc = f"{r.get('product') or 'unknown'} {r.get('version') or ''}".strip()
            for cid in r.get("vulns") or []:
                vuln_ctx.append((str(cid), {
                    "port": port, "service": svc,
                    "banner": (r.get("banner") or "")[:200],
                }))
    else:
        for s in result.get("services") or []:
            if isinstance(s, dict) and isinstance(s.get("port"), int):
                ports.add(s["port"])
        # internetdb (and /host) report the open ports as a top-level list.
        for p in result.get("ports") or []:
            if isinstance(p, int):
                ports.add(p)
        vuln_ctx = [(cid, {}) for cid in top_vulns]

    out: list[Finding] = []
    seen_cves: set[str] = set()
    for cid, ctx in vuln_ctx:
        if cid in seen_cves:
            continue
        seen_cves.add(cid)
        svc, port = ctx.get("service"), ctx.get("port")
        title = f"Known vulnerability {cid}" + (
            f" on {svc} (port {port})" if svc and port is not None else ""
        )
        out.append(Finding(
            tool="shodan_lookup", category="Vulnerability",
            severity=Severity.HIGH,
            title=title,
            description=(
                "Shodan matches this CVE id against the live service banner; "
                "unverified deployment — confirm before acting."
            ),
            evidence={
                "port": port, "service": svc or None,
                "banner": ctx.get("banner") or None,
                "source": result.get("source"),
            },
            cve=cid,
            remediation="Verify the deployed version is affected and patch.",
            target=target, confidence=0.75,
        ))

    for port in sorted(ports):
        info = _SENSITIVE_PORTS.get(port)
        if info is None:
            continue
        title, rem = info
        out.append(Finding(
            tool="shodan_lookup", category="Network Recon",
            severity=Severity.MEDIUM,
            title=title,
            description=f"Shodan reports port {port} open on this IP.",
            evidence={"port": port, "source": result.get("source")},
            remediation=rem, target=target, confidence=0.9,
        ))

    os_name = result.get("os") or (rows[0].get("os") if rows else "")
    tags = result.get("tags") or (rows[0].get("tags") if rows else [])
    if os_name or tags:
        out.append(Finding(
            tool="shodan_lookup", category="Network Recon",
            severity=Severity.INFO,
            title=f"Shodan profile: {os_name or 'unknown OS'}",
            description="Operating system and tags as seen by Shodan.",
            evidence={
                "os": os_name, "tags": list(tags)[:20],
                "source": result.get("source"),
            },
            target=target, confidence=1.0,
        ))

    return out[:10]


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


@register("exploitdb_search")
def _adapt_exploitdb_search(result: dict, target: str) -> list[Finding]:
    """A public exploit for the queried product is HIGH.

    The tool does not confirm the product is deployed (it searches a
    database), so severity stays HIGH and confidence carries the nuance:
    verified entries 0.95, unverified 0.75.
    """
    out: list[Finding] = []
    for e in result.get("exploits", [])[:10]:
        cves = e.get("cves") or []
        out.append(Finding(
            tool="exploitdb_search", category="Vulnerability",
            severity=Severity.HIGH,
            title=f"Public exploit: {e.get('title', '')}",
            description=(
                f"Public exploit-db.com entry for '{target}' "
                f"({e.get('type', '')}, {e.get('platform', '')}, "
                f"{e.get('date_published') or 'unknown date'}, "
                f"{'verified' if e.get('verified') else 'unverified'})."
            ),
            evidence={
                "id": e.get("id"), "url": e.get("url"),
                "type": e.get("type"), "platform": e.get("platform"),
                "date_published": e.get("date_published"),
                "verified": e.get("verified"),
            },
            cve=cves[0] if cves else None,
            remediation=(
                "Verify the deployed version is affected and patch; treat as "
                "exploitable until proven otherwise."
            ),
            target=target,
            confidence=0.95 if e.get("verified") else 0.75,
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


@register("favicon_fingerprint")
def _adapt_favicon_fingerprint(result: dict, target: str) -> list[Finding]:
    """Matched stack = INFO (instalacion por defecto / sin rebrandear).

    Icono desconocido = INFO con los hashes para lookup manual. Sin iconos:
    sin finding (un favicon ausente no es en si una vulnerabilidad).
    """
    out: list[Finding] = []
    for m in result.get("matches", []):
        out.append(Finding(
            tool="favicon_fingerprint", category="Web Security",
            severity=Severity.INFO,
            title=f"Favicon fingerprint: {m.get('stack', '')} default icon at {m.get('path', '')}",
            description=("Icon byte-identical to the official favicon of a known stack. "
                         "Possible default or unrebranded install."),
            evidence={"md5": m.get("md5"), "source": m.get("source")},
            remediation="Confirm the platform and review its CVE surface (cve_correlation).",
            target=target, confidence=0.8,
        ))
    if not out:
        icons = result.get("icons", [])
        if icons:
            first = icons[0]
            out.append(Finding(
                tool="favicon_fingerprint", category="Web Security",
                severity=Severity.INFO,
                title=f"Favicon served at {first.get('path', '')} (unknown to local DB)",
                description=("Icon not present in the local hash database; hashes included "
                             "for manual lookup against public favicon databases."),
                evidence={"md5": first.get("md5"), "sha256": first.get("sha256")},
                remediation="Compare hashes manually against public favicon databases.",
                target=target, confidence=0.6,
            ))
    return out


@register("wayback_urls")
def _adapt_wayback_urls(result: dict, target: str) -> list[Finding]:
    """INFO: historical URL inventory feeds dead-endpoint / takeover hunting."""
    urls = result.get("urls", [])
    if not urls:
        return []
    top_paths = [p["path"] for p in result.get("paths", [])[:10]]
    return [Finding(
        tool="wayback_urls", category="OSINT", severity=Severity.INFO,
        title=f"Wayback Machine: {result.get('count', len(urls))} archived URLs",
        description=(
            f"Historical URL inventory from archive.org (first seen "
            f"{result.get('first_seen') or 'unknown'}, last seen "
            f"{result.get('last_seen') or 'unknown'}). Compare against live "
            "endpoints to hunt dead paths, removed files and takeover candidates."
        ),
        evidence={"count": result.get("count", len(urls)), "top_paths": top_paths},
        remediation=("Review archived-but-dead endpoints for sensitive leftovers "
                     "(backups, .git, old admin panels) and dangling subdomains."),
        target=target, confidence=0.9,
    )]


# Subdomain labels that suggest staging/dev/test/backup/internal usage.
_DNSDUMPSTER_SENSITIVE_LABELS = {
    "admin", "staging", "stage", "dev", "development", "test", "testing",
    "qa", "old", "backup", "bak", "git", "github", "jenkins", "ci",
    "internal", "vpn", "sandbox", "demo", "debug", "tmp",
}


def _sensitive_sub(sub: str) -> bool:
    labels = [l for l in sub.lower().split(".") if l]
    return any(
        lab in _DNSDUMPSTER_SENSITIVE_LABELS or lab.startswith(("old-", "dev-"))
        for lab in labels[:-1]  # ignore the TLD label
    )


@register("dnsdumpster_enum")
def _adapt_dnsdumpster_enum(result: dict, target: str) -> list[Finding]:
    """Subdomain inventory from dnsdumpster.com.

    Sensitive-name subs are MEDIUM at confidence 0.7 — naming only, no
    deployment confirmation; the full inventory rides along as one INFO
    profile finding. Cap 10.
    """
    subs = [s for s in result.get("subdomains") or [] if isinstance(s, str)]
    if not subs:
        return []
    out: list[Finding] = []
    sensitive = sorted({s for s in subs if _sensitive_sub(s)})
    for s in sensitive:
        out.append(Finding(
            tool="dnsdumpster_enum", category="OSINT",
            severity=Severity.MEDIUM,
            title=f"Sensitive subdomain name: {s}",
            description=("Subdomain name suggests staging/dev/test/backup/"
                         "internal usage."),
            evidence={"subdomain": s},
            remediation=("Verify the host is intentional and not a stale or "
                         "dangling record; remove or secure forgotten "
                         "environments."),
            target=target, confidence=0.7,
        ))
    out.append(Finding(
        tool="dnsdumpster_enum", category="OSINT", severity=Severity.INFO,
        title=f"dnsdumpster: {result.get('count', len(subs))} subdomains found",
        description=("Passive subdomain inventory from dnsdumpster.com. "
                     "Cross-check against live DNS/SSL for dangling records."),
        evidence={"count": result.get("count", len(subs)), "top": subs[:20]},
        remediation="Review the full list for forgotten or dangling subdomains.",
        target=target, confidence=0.9,
    ))
    return out[:10]


@register("publicwww_search")
def _adapt_publicwww_search(result: dict, target: str) -> list[Finding]:
    """Exposed attack surface from publicwww.com.

    Sensitive-name hosts are MEDIUM at confidence 0.7 (naming only, no
    deployment confirmation — same criterion as the dnsdumpster adapter,
    reusing _sensitive_sub); the inventory rides along as one INFO profile
    finding. Cap 10.
    """
    hosts = [h for h in result.get("hosts") or [] if isinstance(h, str)]
    if not hosts:
        return []
    out: list[Finding] = []
    sensitive = sorted({h for h in hosts if _sensitive_sub(h)})
    for h in sensitive:
        out.append(Finding(
            tool="publicwww_search", category="OSINT",
            severity=Severity.MEDIUM,
            title=f"Sensitive subdomain name: {h}",
            description=("PublicWWW has seen this host; the name suggests "
                         "staging/dev/test/backup/internal usage."),
            evidence={"host": h},
            remediation=("Verify the host is intentional and not a stale or "
                         "dangling record; remove or secure forgotten "
                         "environments."),
            target=target, confidence=0.7,
        ))
    out.append(Finding(
        tool="publicwww_search", category="OSINT", severity=Severity.INFO,
        title=f"PublicWWW: {result.get('count', len(hosts))} URLs indexed for the domain",
        description=("Passive exposure inventory from publicwww.com. "
                     "Cross-check hosts and tech against live DNS/SSL for "
                     "dangling records."),
        evidence={
            "count": result.get("count", len(hosts)),
            "top_hosts": hosts[:20],
            "technologies": (result.get("technologies") or [])[:20],
        },
        remediation="Review the full inventory for forgotten or dangling hosts.",
        target=target, confidence=0.9,
    ))
    return out[:10]


@register("urlscan_lookup")
def _adapt_urlscan_lookup(result: dict, target: str) -> list[Finding]:
    """Passive scan inventory from urlscan.io.

    Sensitive-name hosts are MEDIUM at confidence 0.7 (naming only, no
    deployment confirmation — same criterion as the dnsdumpster/publicwww
    adapters, reusing _sensitive_sub); the inventory rides along as one INFO
    profile finding. Cap 10.
    """
    hosts = [h for h in result.get("hosts") or [] if isinstance(h, str)]
    if not hosts:
        return []
    out: list[Finding] = []
    sensitive = sorted({h for h in hosts if _sensitive_sub(h)})
    for h in sensitive:
        out.append(Finding(
            tool="urlscan_lookup", category="OSINT",
            severity=Severity.MEDIUM,
            title=f"Sensitive subdomain name: {h}",
            description=("urlscan.io has seen this host; the name suggests "
                         "staging/dev/test/backup/internal usage."),
            evidence={"host": h},
            remediation=("Verify the host is intentional and not a stale or "
                         "dangling record; remove or secure forgotten "
                         "environments."),
            target=target, confidence=0.7,
        ))
    out.append(Finding(
        tool="urlscan_lookup", category="OSINT", severity=Severity.INFO,
        title=f"URLScan: {result.get('count', len(hosts))} scans found for the domain",
        description=("Passive scan inventory from urlscan.io. "
                     "Cross-check hosts against live DNS/SSL for dangling "
                     "records."),
        evidence={
            "count": result.get("count", len(hosts)),
            "top_hosts": hosts[:20],
        },
        remediation="Review the full inventory for forgotten or dangling hosts.",
        target=target, confidence=0.9,
    ))
    return out[:10]


@register("greynoise_lookup")
def _adapt_greynoise_lookup(result: dict, target: str) -> list[Finding]:
    """IP reputation from the GreyNoise community dataset.

    Known malicious scanner: HIGH. Any known scanner: LOW — expected
    probing noise, context not alarm. RIOT-only (benign infra): INFO
    profile. No data / error: no findings. Cap 1.
    """
    if not result.get("found"):
        return []
    ip = result.get("ip", "")
    classification = result.get("classification") or ""
    name = result.get("name") or ""
    last_seen = result.get("last_seen") or ""
    if result.get("noise") and classification == "malicious":
        return [Finding(
            tool="greynoise_lookup", category="OSINT", severity=Severity.HIGH,
            title=f"IP {ip} is a known malicious scanner (GreyNoise)",
            description=(f"GreyNoise classifies {ip} as '{classification}' "
                         f"(last seen {last_seen or 'unknown'}). Traffic from "
                         "this IP is very likely automated scanning."),
            evidence={"ip": ip, "classification": classification,
                      "name": name, "last_seen": last_seen},
            remediation=("Correlate with access logs; if this IP hit the "
                         "target, treat the events as scanner noise and "
                         "consider blocking it."),
            target=target, confidence=0.8,
        )]
    if result.get("noise"):
        return [Finding(
            tool="greynoise_lookup", category="OSINT", severity=Severity.LOW,
            title=f"IP {ip} is a known scanner (GreyNoise)",
            description=(f"GreyNoise has observed {ip} scanning the internet "
                         f"(classification '{classification or 'unknown'}', "
                         f"last seen {last_seen or 'unknown'})."),
            evidence={"ip": ip, "classification": classification,
                      "name": name, "last_seen": last_seen},
            remediation=("Expect probe noise from this IP in logs; block it "
                         "if it is not your own infrastructure."),
            target=target, confidence=0.7,
        )]
    return [Finding(
        tool="greynoise_lookup", category="OSINT", severity=Severity.INFO,
        title=f"IP {ip} is benign internet-wide infrastructure (GreyNoise RIOT)",
        description=(f"{name or 'The IP'} belongs to the RIOT dataset of "
                     "benign cloud/hosting infrastructure."),
        evidence={"ip": ip, "name": name, "classification": classification},
        remediation="No action; use this context to filter false positives.",
        target=target, confidence=0.9,
    )]


# Email local parts that indicate an admin/privileged role account.
_HUNTER_SENSITIVE_LOCALS = {
    "admin", "root", "ciso", "ceo", "director", "it", "security",
    "backup", "git",
}


@register("hunter_email_finder")
def _adapt_hunter_email_finder(result: dict, target: str) -> list[Finding]:
    """Email exposure surface from Hunter Domain Search.

    Sensitive local parts (admin@, ciso@, ...) and decision makers are
    MEDIUM at confidence 0.7 — confirmed accounts with a sensitive role;
    the full inventory rides along as one INFO profile finding. Cap 10.
    """
    emails = [e for e in result.get("emails") or [] if isinstance(e, dict)]
    if not emails:
        return []
    out: list[Finding] = []
    flagged: set[str] = set()
    for e in emails:
        email = e.get("email")
        if not isinstance(email, str) or not email:
            continue
        local = email.split("@", 1)[0].lower()
        if local in _HUNTER_SENSITIVE_LOCALS or e.get("decision_maker"):
            flagged.add(email)
    for email in sorted(flagged):
        e = next((x for x in emails if x.get("email") == email), {})
        out.append(Finding(
            tool="hunter_email_finder", category="OSINT",
            severity=Severity.MEDIUM,
            title=f"Sensitive-role email exposed: {email}",
            description=(f"Hunter has confirmed this address on the domain "
                         f"(confidence {e.get('confidence', 'unknown')}). "
                         "Primary target for phishing and credential stuffing."),
            evidence={"email": email, "position": e.get("position") or "",
                      "first_name": e.get("first_name") or "",
                      "last_name": e.get("last_name") or "",
                      "confidence": e.get("confidence")},
            remediation=("Harden login (MFA), monitor for phishing, and review "
                         "whether the address needs to be public."),
            target=target, confidence=0.7,
        ))
    out.append(Finding(
        tool="hunter_email_finder", category="OSINT", severity=Severity.INFO,
        title=f"Hunter: {result.get('count', len(emails))} known emails for the domain",
        description=("Passive email exposure inventory from hunter.io. "
                     "Cross-check against real mailbox policy and anti-"
                     "phishing posture."),
        evidence={"count": result.get("count", len(emails)),
                  "top": [e.get("email") for e in emails[:20] if isinstance(e, dict)][:20]},
        remediation=("Review the full list for forgotten accounts or roles "
                     "that should not be exposed."),
        target=target, confidence=0.9,
    ))
    return out[:10]


# ── grep.app code search ───────────────────────────────────────
_GREPPAPP_SENSITIVE_PATHS = (
    ".env", ".pem", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".netrc", "credentials", "secrets", "known_hosts",
)


def _grepapp_sensitive_path(path: str) -> bool:
    p = (path or "").lower()
    base = p.rsplit("/", 1)[-1]
    if any(s in base for s in _GREPPAPP_SENSITIVE_PATHS):
        return True
    if base.endswith((".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")):
        return True
    if ".env" in base or base.startswith(".env"):
        return True
    return False


@register("grepapp_search")
def _adapt_grepapp_search(result: dict, target: str) -> list[Finding]:
    """Term found in public code is an exposure signal.

    A hit inside a credential/secret-looking file (.env, id_rsa, *.pem,
    credentials, ...) is MEDIUM at confidence 0.7 — the term plausibly sits
    next to real material; any other hit is only an INFO profile (the full
    inventory rides along). Cap 10.
    """
    repos = [r for r in result.get("repos") or [] if isinstance(r, dict)]
    if not repos:
        return []
    out: list[Finding] = []
    sensitive = sorted({f"{r.get('repo')}:{r.get('path')}" for r in repos
                        if _grepapp_sensitive_path(str(r.get("path") or ""))})
    for loc in sensitive:
        r = next((x for x in repos if f"{x.get('repo')}:{x.get('path')}" == loc), {})
        out.append(Finding(
            tool="grepapp_search", category="OSINT",
            severity=Severity.MEDIUM,
            title=f"Sensitive file mentions the term: {loc}",
            description=(f"The queried term appears in a public repo file that "
                         f"by name holds credentials or secrets ({loc}). "
                         "Possible leaked material in public code."),
            evidence={"repo": r.get("repo"), "path": r.get("path"),
                      "branch": r.get("branch") or "",
                      "total_matches": r.get("total_matches")},
            remediation=("Assume the material is public: rotate any secret that "
                         "could sit in that file and review repo visibility."),
            target=target, confidence=0.7,
        ))
    out.append(Finding(
        tool="grepapp_search", category="OSINT", severity=Severity.INFO,
        title=f"grep.app: {result.get('count', len(repos))} public repos mention the term",
        description=("Passive code-exposure inventory from grep.app over public "
                     "GitHub data. Review the listed files for anything that "
                     "should not be public."),
        evidence={"count": result.get("count", len(repos)),
                  "total": result.get("total"),
                  "top": [f"{r.get('repo')}:{r.get('path')}" for r in repos[:20]],
                  "languages": result.get("languages") or []},
        remediation=("Audit the exposed files; move secrets to a private repo "
                     "or rotate them."),
        target=target, confidence=0.9,
    ))
    return out[:10]


# ── Vulners advisory search ─────────────────────────────────────
_VULNERS_SEVERITY_MAP = {
    "critical": (Severity.HIGH, 0.75),
    "high": (Severity.HIGH, 0.75),
    "medium": (Severity.MEDIUM, 0.7),
    "low": (Severity.LOW, 0.6),
}


@register("vulners_search")
def _adapt_vulners_search(result: dict, target: str) -> list[Finding]:
    """Advisories from Vulners for the queried product or CVE.

    The tool does not confirm deployment (it searches a database), so
    severity maps with reduced confidence: critical/high HIGH 0.75, medium
    MEDIUM 0.7, low/unknown LOW 0.6. Dedup by id, cap 10.
    """
    vulns = [v for v in result.get("vulns") or [] if isinstance(v, dict)]
    out: list[Finding] = []
    seen: set[str] = set()
    for v in vulns:
        vid = str(v.get("id") or "")
        if not vid or vid in seen:
            continue
        seen.add(vid)
        sev = str(v.get("severity") or "").lower()
        severity, confidence = _VULNERS_SEVERITY_MAP.get(sev, (Severity.LOW, 0.5))
        out.append(Finding(
            tool="vulners_search", category="Vulnerability",
            severity=severity,
            title=f"{vid}: {str(v.get('title') or 'advisory')[:100]}",
            description=str(v.get("description") or "")[:300],
            evidence={"id": vid, "type": v.get("type") or "",
                      "severity": sev or "unknown",
                      "published": v.get("published"),
                      "url": v.get("url") or ""},
            remediation=("Patch or mitigate following the advisory references; "
                        "verify whether the queried product/version is deployed."),
            target=target, confidence=confidence,
        ))
    return out[:10]


_DNS_HYGIENE_META = {
    # id: (severity, confidence, title, remediation)
    "spf_permissive_all": (
        Severity.HIGH, 0.95, "SPF is fully permissive (+all)",
        "Replace '+all' with '-all' so only listed senders are authorized.",
    ),
    "spf_missing": (
        Severity.MEDIUM, 0.8, "No SPF record published",
        "Publish a v=spf1 TXT covering all legitimate senders, ending in -all.",
    ),
    "spf_multiple_records": (
        Severity.MEDIUM, 0.95, "Multiple SPF records (undefined behavior)",
        "Consolidate to a single v=spf1 TXT record at the apex (RFC 7208).",
    ),
    "spf_no_hardfail": (
        Severity.LOW, 0.8, "SPF has no terminal -all",
        "End the SPF mechanism list with -all.",
    ),
    "dmarc_missing": (
        Severity.MEDIUM, 0.8, "No DMARC record published",
        "Publish _dmarc TXT starting with v=DMARC1; p=quarantine or p=reject plus rua reporting.",
    ),
    "dmarc_p_none": (
        Severity.MEDIUM, 0.95, "DMARC policy is monitor-only (p=none)",
        "Move to p=quarantine and then p=reject once spoofing volume is known.",
    ),
    "dmarc_sp_weak": (
        Severity.LOW, 0.9, "DMARC subdomain policy weaker than apex",
        "Align sp= with p= or document why subdomains stay weaker.",
    ),
    "dmarc_pct_partial": (
        Severity.LOW, 0.9, "DMARC pct limits enforcement",
        "Raise pct= to 100 once monitoring looks clean.",
    ),
    "dkim_missing": (
        Severity.MEDIUM, 0.8, "No DKIM key under common selectors",
        "Enable DKIM in the mail provider and publish the public key.",
    ),
    "dkim_empty_key": (
        Severity.LOW, 0.9, "DKIM selector with empty public key",
        "Publish a real key for that selector or remove the record.",
    ),
    "dkim_key_weak": (
        Severity.HIGH, 0.95, "Weak DKIM RSA key",
        "Re-sign with a 2048-bit (or larger) DKIM key.",
    ),
    "dkim_key_legacy": (
        Severity.LOW, 0.9, "Legacy DKIM RSA key length",
        "Rotate to a 2048-bit DKIM key at next re-sign.",
    ),
    "dnskey_weak": (
        Severity.HIGH, 0.95, "Weak DNSKEY",
        "Re-key the zone with a 2048-bit (or larger) key.",
    ),
    "dnskey_legacy": (
        Severity.LOW, 0.9, "Legacy DNSKEY length",
        "Re-key the zone with a 2048-bit key when convenient.",
    ),
}


@register("dns_zone_hygiene")
def _adapt_dns_zone_hygiene(result: dict, target: str) -> list[Finding]:
    """Map zone-hygiene issue ids to severities; dedup by id + detail."""
    out: list[Finding] = []
    seen: set[str] = set()
    for i in result.get("issues", []):
        iid = i.get("id", "")
        meta = _DNS_HYGIENE_META.get(iid)
        if meta is None:
            continue
        key = f"{iid}|{i.get('detail', '')}"
        if key in seen:
            continue
        seen.add(key)
        sev, conf, title, remediation = meta
        out.append(Finding(
            tool="dns_zone_hygiene", category="Email Security",
            severity=sev,
            title=title,
            description=i.get("detail", ""),
            evidence={"check": iid},
            remediation=remediation,
            target=target, confidence=conf,
        ))
    return out[:20]


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
