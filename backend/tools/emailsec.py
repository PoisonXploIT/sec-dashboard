"""Email security and DNS hardening tools."""
import asyncio
import base64
import socket
from urllib.parse import urlparse

import aiohttp
import dns.resolver

from backend.proxy import get_aiohttp_connector
from backend.tools.osint import _is_ip


# ── DNSSEC Checker ─────────────────────────────────────────────
async def dnssec_checker(target: str, **kw) -> dict:
    """Check DNSSEC status for a domain."""
    # If it's an IP, DNSSEC doesn't apply
    try:
        socket.inet_pton(socket.AF_INET, target)
        return {"target": target, "error": "DNSSEC applies to domains, not IPs"}
    except socket.error:
        pass

    results = {"target": target, "dnssec_enabled": False, "details": {}}

    # Check for DNSKEY records
    try:
        answers = await asyncio.to_thread(
            dns.resolver.resolve, target, "DNSKEY", lifetime=10
        )
        keys = []
        for rdata in answers:
            key_type = "KSK" if rdata.flags == 257 else "ZSK" if rdata.flags == 256 else f"flags={rdata.flags}"
            keys.append({
                "type": key_type,
                "protocol": rdata.protocol,
                "algorithm": rdata.algorithm,
            })
        results["dnssec_enabled"] = len(keys) > 0
        results["details"]["dnskey_records"] = keys
        results["details"]["key_count"] = len(keys)
    except dns.resolver.NoAnswer:
        results["details"]["dnskey"] = "No DNSKEY records found"
    except dns.resolver.NXDOMAIN:
        return {"target": target, "error": "Domain does not exist"}
    except Exception as e:
        results["details"]["dnskey_error"] = str(e)[:100]

    # Check for DS records at parent zone
    try:
        ds_answers = await asyncio.to_thread(
            dns.resolver.resolve, target, "DS", lifetime=10
        )
        ds_records = []
        for rdata in ds_answers:
            ds_records.append({
                "key_tag": rdata.key_tag,
                "algorithm": rdata.algorithm,
                "digest_type": rdata.digest_type,
            })
        results["details"]["ds_records"] = ds_records
        results["details"]["ds_count"] = len(ds_records)
    except dns.resolver.NoAnswer:
        results["details"]["ds"] = "No DS records at parent zone (DNSSEC not delegated)"
    except Exception:
        results["details"]["ds"] = "Could not query DS records"

    # Check for RRSIG on A record (signed response)
    try:
        a_answers = await asyncio.to_thread(
            dns.resolver.resolve, target, "A", lifetime=10,
            raise_on_no_answer=False
        )
        if a_answers.rrset and a_answers.response.answer:
            has_rrsig = any(rdata.rdtype == dns.rdatatype.RRSIG for rdata in a_answers.response.answer)
            results["details"]["a_record_signed"] = has_rrsig
            if has_rrsig:
                results["details"]["signature"] = "A records are signed (RRSIG present)"
    except Exception:
        results["details"]["a_record_signed"] = "Could not verify"

    if results["dnssec_enabled"]:
        results["recommendation"] = "DNSSEC is enabled. Ensure DS records are published at parent zone for full chain of trust."
    else:
        results["recommendation"] = "DNSSEC is NOT enabled. Enable it in your DNS provider to prevent DNS spoofing/cache poisoning."

    return results


# ── Email Security (SPF + DKIM + DMARC) ────────────────────────
async def email_security(target: str, **kw) -> dict:
    """Check SPF, DKIM, and DMARC records for a domain."""
    try:
        socket.inet_pton(socket.AF_INET, target)
        return {"target": target, "error": "Email security checks require a domain, not an IP"}
    except socket.error:
        pass

    results = {"target": target, "spf": {}, "dkim": {}, "dmarc": {}}

    # SPF
    try:
        txt_answers = await asyncio.to_thread(
            dns.resolver.resolve, target, "TXT", lifetime=10
        )
        spf_record = None
        all_txt = []
        for rdata in txt_answers:
            val = str(rdata).strip('"')
            all_txt.append(val)
            if val.startswith("v=spf1"):
                spf_record = val

        if spf_record:
            results["spf"] = {
                "present": True,
                "record": spf_record,
                "mechanisms": _parse_spf(spf_record),
            }
        else:
            results["spf"] = {"present": False, "recommendation": "Add SPF record: v=spf1 include:_spf.mx.cloudflare.net ~all"}
    except dns.resolver.NoAnswer:
        results["spf"] = {"present": False, "error": "No TXT records found"}
    except Exception as e:
        results["spf"] = {"present": False, "error": str(e)[:80]}

    # DKIM -- check common selectors
    dkim_selectors = ["default", "google", "cf2024-1", "selector1", "selector2", "s1", "s2"]
    dkim_found = []
    for selector in dkim_selectors:
        try:
            dkim_answers = await asyncio.to_thread(
                dns.resolver.resolve, f"{selector}._domainkey.{target}", "TXT", lifetime=5
            )
            for rdata in dkim_answers:
                val = str(rdata).strip('"')
                if val.startswith("v=DKIM1"):
                    dkim_found.append({"selector": selector, "record": val[:200]})
        except Exception:
            pass

    if dkim_found:
        results["dkim"] = {
            "present": True,
            "selectors": dkim_found,
            "count": len(dkim_found),
        }
    else:
        results["dkim"] = {
            "present": False,
            "recommendation": "Enable DKIM in your email provider. Common selectors checked: " + ", ".join(dkim_selectors),
        }

    # DMARC
    try:
        dmarc_answers = await asyncio.to_thread(
            dns.resolver.resolve, f"_dmarc.{target}", "TXT", lifetime=10
        )
        dmarc_record = None
        for rdata in dmarc_answers:
            val = str(rdata).strip('"')
            if val.startswith("v=DMARC1"):
                dmarc_record = val

        if dmarc_record:
            results["dmarc"] = {
                "present": True,
                "record": dmarc_record,
                "policy": _parse_dmarc(dmarc_record),
            }
        else:
            results["dmarc"] = {"present": False, "recommendation": "Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:admin@yourdomain.com"}
    except dns.resolver.NoAnswer:
        results["dmarc"] = {"present": False, "recommendation": "Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:admin@yourdomain.com"}
    except Exception as e:
        results["dmarc"] = {"present": False, "error": str(e)[:80]}

    # Summary
    spf_ok = results["spf"].get("present", False)
    dkim_ok = results["dkim"].get("present", False)
    dmarc_ok = results["dmarc"].get("present", False)
    results["summary"] = {
        "spf": "OK" if spf_ok else "MISSING",
        "dkim": "OK" if dkim_ok else "MISSING",
        "dmarc": "OK" if dmarc_ok else "MISSING",
        "score": sum([spf_ok, dkim_ok, dmarc_ok]),
        "total": 3,
    }

    return results


def _parse_spf(record: str) -> list:
    """Extract SPF mechanisms."""
    parts = record.split()
    mechanisms = []
    for p in parts[1:]:  # skip v=spf1
        if p.startswith("include:"):
            mechanisms.append({"type": "include", "value": p[8:]})
        elif p.startswith("ip4:"):
            mechanisms.append({"type": "ip4", "value": p[4:]})
        elif p.startswith("ip6:"):
            mechanisms.append({"type": "ip6", "value": p[4:]})
        elif p in ("~all", "-all", "+all", "?all"):
            mechanisms.append({"type": "all", "policy": p})
        elif p.startswith("mx"):
            mechanisms.append({"type": "mx", "value": p})
        elif p.startswith("a:"):
            mechanisms.append({"type": "a", "value": p[2:]})
        else:
            mechanisms.append({"type": "other", "value": p})
    return mechanisms


def _parse_dmarc(record: str) -> dict:
    """Extract DMARC policy details."""
    policy = {}
    parts = record.split(";")
    for p in parts:
        p = p.strip()
        if p.startswith("p="):
            policy["policy"] = p[2:]
        elif p.startswith("rua="):
            policy["reports"] = p[4:]
        elif p.startswith("ruf="):
            policy["forensic_reports"] = p[4:]
        elif p.startswith("sp="):
            policy["subdomain_policy"] = p[3:]
        elif p.startswith("pct="):
            policy["percentage"] = p[4:]
        elif p.startswith("fo="):
            policy["forensic_options"] = p[3:]
    return policy


# ── HTTP Methods Checker ───────────────────────────────────────
async def http_methods(target: str, **kw) -> dict:
    """Check which HTTP methods are allowed."""
    if not target.startswith("http"):
        target = f"https://{target}"

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
    results = {"target": target, "methods": [], "dangerous": []}

    connector = get_aiohttp_connector()

    # First try OPTIONS
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), connector=connector) as session:
            async with session.options(target, allow_redirects=False) as resp:
                allow_header = resp.headers.get("Allow", "")
                if allow_header:
                    results["options_allow_header"] = allow_header
                    results["options_status"] = resp.status
    except Exception as e:
        results["options_error"] = str(e)[:80]

    # Test each method individually
    for method in methods:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), connector=connector) as session:
                async with session.request(method, target, allow_redirects=False) as resp:
                    allowed = resp.status < 400 or resp.status == 405
                    entry = {
                        "method": method,
                        "status": resp.status,
                        "allowed": resp.status < 400,
                    }
                    if resp.headers.get("Allow"):
                        entry["allow_header"] = resp.headers["Allow"]
                    results["methods"].append(entry)

                    if method in ("PUT", "DELETE", "TRACE") and resp.status < 400:
                        results["dangerous"].append({
                            "method": method,
                            "status": resp.status,
                            "risk": "HIGH" if method == "TRACE" else "MEDIUM",
                            "reason": f"{method} should be disabled. TRACE enables XST attacks, PUT/DELETE allow file modification."
                        })
        except Exception as e:
            results["methods"].append({
                "method": method,
                "status": None,
                "allowed": False,
                "error": str(e)[:80],
            })

    results["dangerous_count"] = len(results["dangerous"])
    if not results["dangerous"]:
        results["recommendation"] = "No dangerous HTTP methods detected. Good."
    else:
        results["recommendation"] = f"{len(results['dangerous'])} dangerous method(s) detected. Disable them in your web server config."

    return results


# ── Robots.txt Analyzer ────────────────────────────────────────
async def robots_analyzer(target: str, **kw) -> dict:
    """Analyze robots.txt for sensitive paths and misconfigurations."""
    if not target.startswith("http"):
        target = f"https://{target}"

    robots_url = f"{target}/robots.txt"
    results = {"target": target, "url": robots_url, "found": False, "rules": [], "sensitive_paths": [], "issues": []}

    connector = get_aiohttp_connector()

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), connector=connector) as session:
            async with session.get(robots_url) as resp:
                if resp.status != 200:
                    results["error"] = f"robots.txt returned HTTP {resp.status}"
                    results["recommendation"] = "Create a robots.txt file with appropriate rules."
                    return results

                content = await resp.text()
                results["found"] = True
                results["content"] = content[:2000]
                results["content_length"] = len(content)

    except Exception as e:
        results["error"] = str(e)[:80]
        results["recommendation"] = "Could not fetch robots.txt. Ensure it exists."
        return results

    # Parse rules
    lines = content.split("\n")
    current_agent = "*"
    sensitive_patterns = [
        "admin", "wp-admin", "wp-login", "login", "config", "backup",
        "secret", "private", "internal", "api", "panel", "dashboard",
        ".git", ".env", "phpinfo", "test", "dev", "staging", "database",
        "db", "sql", "dump", "password", "key", "token", "cert",
    ]

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("user-agent:"):
            current_agent = line.split(":", 1)[1].strip()
        elif line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                results["rules"].append({"agent": current_agent, "rule": "Disallow", "path": path})
                # Check for sensitive paths
                path_lower = path.lower()
                for pattern in sensitive_patterns:
                    if pattern in path_lower:
                        results["sensitive_paths"].append({
                            "path": path,
                            "pattern": pattern,
                            "risk": "MEDIUM",
                            "reason": f"Disallowed path contains sensitive keyword: '{pattern}'. This reveals the path exists."
                        })
                        break
        elif line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                results["rules"].append({"agent": current_agent, "rule": "Allow", "path": path})

    # Check for issues
    if not results["rules"]:
        results["issues"].append({"type": "empty", "severity": "LOW", "message": "robots.txt has no rules"})

    if "Disallow: /" in content and "Allow: /" not in content:
        results["issues"].append({"type": "block_all", "severity": "HIGH", "message": "robots.txt blocks all crawlers from entire site"})

    results["sensitive_count"] = len(results["sensitive_paths"])
    results["rule_count"] = len(results["rules"])

    if results["sensitive_paths"]:
        results["recommendation"] = f"robots.txt exposes {len(results['sensitive_paths'])} sensitive paths. Remove Disallow rules for paths that shouldn't be publicly known."
    else:
        results["recommendation"] = "No sensitive paths detected in robots.txt. Good."

    return results


# ── CAA Checker ────────────────────────────────────────────────
async def caa_checker(target: str, **kw) -> dict:
    """Check CAA records for a domain."""
    try:
        socket.inet_pton(socket.AF_INET, target)
        return {"target": target, "error": "CAA records apply to domains, not IPs"}
    except socket.error:
        pass

    results = {"target": target, "caa_records": [], "found": False}

    try:
        answers = await asyncio.to_thread(
            dns.resolver.resolve, target, "CAA", lifetime=10
        )
        for rdata in answers:
            # CAA record has flags, tag, and value
            entry = {
                "flags": rdata.flags,
                "tag": str(rdata.tag),
                "value": str(rdata.value),
            }
            results["caa_records"].append(entry)
        results["found"] = len(results["caa_records"]) > 0
        results["count"] = len(results["caa_records"])
    except dns.resolver.NoAnswer:
        results["found"] = False
        results["recommendation"] = "No CAA records found. Add CAA records to restrict which CAs can issue certificates: e.g. issue 'letsencrypt.org'"
    except dns.resolver.NXDOMAIN:
        return {"target": target, "error": "Domain does not exist"}
    except Exception as e:
        # Some DNS servers don't support CAA queries
        results["error"] = str(e)[:80]
        results["recommendation"] = "Could not query CAA records. Your DNS provider may not support CAA."
        return results

    if results["found"]:
        issuers = [r["value"] for r in results["caa_records"] if r["tag"] == "issue"]
        wildcards = [r["value"] for r in results["caa_records"] if r["tag"] == "issuewild"]
        results["issuers"] = issuers
        results["wildcard_issuers"] = wildcards
        results["recommendation"] = f"CAA records found. Only these CAs can issue certificates: {', '.join(issuers)}"
    else:
        results["recommendation"] = "No CAA records found. Any CA can issue certificates for this domain. Add CAA records to restrict."

    return results


# ── DNS Zone Hygiene ───────────────────────────────────────────
# Depth tool over the email/zone trust chain: SPF permissiveness, DKIM
# selector brute + public key strength, DMARC policy and DNSKEY length.
# Best-effort like the rest of the suite: a failed query degrades to a
# status; 'missing' conclusions are only emitted for definitive answers.
_DKIM_SELECTORS = [
    "default", "google", "cf2024-1", "selector1", "selector2",
    "s1", "s2", "mail", "mta", "sip", "krs", "dkim", "mx",
]


def _tlv(data: bytes, off: int) -> tuple[int, int, int]:
    """Read one DER TLV header; returns (tag, content_len, content_offset)."""
    tag = data[off]
    ln = data[off + 1]
    if ln < 0x80:
        return tag, ln, off + 2
    n = ln & 0x7F
    length = int.from_bytes(data[off + 2:off + 2 + n], "big")
    return tag, length, off + 2 + n


def _spki_key_bits(p_b64: str) -> tuple[str, int | None]:
    """Classify a DKIM public key (SPKI DER).

    Returns ('rsa', bits), ('ec', 256) for ecdsa-with-SHA256 (RFC 6945
    mandates P-256) or ('unknown', None) when it cannot be derived.
    """
    try:
        der = base64.b64decode(p_b64.encode("ascii"), validate=True)
    except Exception:
        return "unknown", None
    if len(der) < 8 or der[0] != 0x30:
        return "unknown", None
    try:
        _, _, off = _tlv(der, 0)            # SubjectPublicKeyInfo SEQUENCE
        atag, alen, aoff = _tlv(der, off)   # AlgorithmIdentifier SEQUENCE
        if atag != 0x30:
            return "unknown", None
        otag, olen, ooff = _tlv(der, aoff)  # OID inside AlgorithmIdentifier
        oid = der[ooff:ooff + olen]
        bit_off = aoff + alen               # BIT STRING right after the algid
        if der[bit_off] != 0x03:
            return "unknown", None
        _, blen, boff = _tlv(der, bit_off)
        mpi = der[boff:boff + blen][1:]     # skip the unused-bits byte
        if oid == bytes.fromhex("2a864886f70d010100"):  # rsaEncryption
            return "rsa", int.from_bytes(mpi, "big").bit_length()
        if oid == bytes.fromhex("2a8648ce3d030107"):    # ecdsa-with-SHA256
            return "ec", 256
        return "unknown", None
    except Exception:
        return "unknown", None


_DNSKEY_EC_BITS = {5: 256}  # algorithm 5 = ECDSAP256 (RFC 8624)


def _dnskey_bits(algorithm: int, publickey_b64: str) -> int | None:
    """Key bit length from a DKIM/DNSKEY RDATA; None when not derivable.

    RSA-family algorithms (1, 3) carry the modulus as a base-128 MPI in the
    Public Key field, so its big-endian value gives the exact bit length.
    """
    if algorithm in _DNSKEY_EC_BITS:
        return _DNSKEY_EC_BITS[algorithm]
    if algorithm not in (1, 3):
        return None
    try:
        key = base64.b64decode(publickey_b64)
    except Exception:
        return None
    if not key:
        return None
    return int.from_bytes(key, "big").bit_length()


def _spf_summary(record: str) -> dict:
    """Summarize one v=spf1 record: permissive/hardfail + mechanism count."""
    mechs = _parse_spf(record)
    policies = [m.get("policy") for m in mechs if m.get("type") == "all"]
    return {
        "permissive": "+all" in policies,
        "hardfail": "-all" in policies,
        "mechanism_count": len(mechs),
    }


def _dmarc_issues(record: str) -> list[str]:
    """Issue ids derivable from one v=DMARC1 record."""
    pol = _parse_dmarc(record)
    p = str(pol.get("policy", ""))
    sp = str(pol.get("subdomain_policy", ""))
    issues: list[str] = []
    if p == "none":
        issues.append("dmarc_p_none")
    elif p in ("quarantine", "reject"):
        try:
            if int(str(pol.get("percentage", "")).strip()) < 100:
                issues.append("dmarc_pct_partial")
        except ValueError:
            pass
    order = {"none": 0, "quarantine": 1, "reject": 2}
    if p in order and sp in order and sp != p and order[sp] < order[p]:
        issues.append("dmarc_sp_weak")
    return issues


def _dkim_parse(record: str) -> dict:
    """Parse one v=DKIM1 record → {'empty_key': bool, 'key_b64': str}."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    p = tags.get("p", "")
    return {"empty_key": p == "", "key_b64": p}


async def _hygiene_txt(name: str, lifetime: float = 8.0) -> tuple[str, list]:
    """TXT query for one name; (status, records). Best-effort, never raises."""
    try:
        answers = await asyncio.to_thread(
            dns.resolver.resolve, name, "TXT", lifetime=lifetime
        )
        return "ok", [str(rdata).strip('"') for rdata in answers]
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        return "noanswer", []
    except Exception:
        return "error", []


async def _hygiene_dnskey(domain: str, lifetime: float = 8.0) -> tuple[str, list]:
    """DNSKEY query for the apex; (status, [{algorithm, flags, publickey}])."""
    try:
        answers = await asyncio.to_thread(
            dns.resolver.resolve, domain, "DNSKEY", lifetime=lifetime
        )
        return "ok", [
            {"algorithm": r.algorithm, "flags": r.flags, "publickey": r.publickey}
            for r in answers
        ]
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        return "noanswer", []
    except Exception:
        return "error", []


async def dns_zone_hygiene(target: str, **kw) -> dict:
    """DNS zone hygiene: SPF permissiveness, DKIM selector brute + key
    strength, DMARC policy and DNSKEY length.

    External failures degrade to per-area statuses; 'missing' conclusions
    are only emitted for definitive answers (ok/noanswer), never on timeout.
    """
    t = target or ""
    if "://" in t:
        t = urlparse(t).netloc or t
    host = t.split("/")[0].split(":")[0].strip().lower()
    if not host or _is_ip(host):
        return {"target": host, "error": "DNS hygiene requires a domain, not an IP"}

    apex_status, apex_txt = await _hygiene_txt(host)
    if apex_status == "nxdomain":
        return {"target": host, "error": "Domain does not exist"}

    issues: list[dict] = []

    # ── SPF (TXT at the apex) ──
    spf_records = [r for r in apex_txt if r.startswith("v=spf1")]
    spf: dict = {"present": bool(spf_records)}
    if apex_status == "error":
        spf["status"] = "error"
    if not spf_records and apex_status in ("ok", "noanswer"):
        issues.append({"id": "spf_missing", "detail": "No v=spf1 record at the zone apex"})
    if len(spf_records) > 1:
        issues.append({
            "id": "spf_multiple_records",
            "detail": f"{len(spf_records)} v=spf1 records published (RFC 7208 requires one)",
        })
    if spf_records:
        summary = _spf_summary(spf_records[0])
        spf.update({
            "terminal_hardfail": summary["hardfail"],
            "mechanism_count": summary["mechanism_count"],
        })
        if summary["permissive"]:
            issues.append({
                "id": "spf_permissive_all",
                "detail": "'+all' authorizes every host on the internet to send as this domain",
            })
        elif not summary["hardfail"]:
            issues.append({
                "id": "spf_no_hardfail",
                "detail": "No terminal '-all': unauthorized senders are only soft-failed or neutral",
            })

    # ── DMARC (TXT at _dmarc.<host>) ──
    dmarc_status, dmarc_txt = await _hygiene_txt(f"_dmarc.{host}")
    dmarc_records = [r for r in dmarc_txt if r.startswith("v=DMARC1")]
    dmarc: dict = {"present": bool(dmarc_records)}
    if dmarc_status == "error":
        dmarc["status"] = "error"
    if not dmarc_records and dmarc_status in ("ok", "noanswer"):
        issues.append({"id": "dmarc_missing", "detail": "No v=DMARC1 record at _dmarc"})
    if dmarc_records:
        pol = _parse_dmarc(dmarc_records[0])
        dmarc.update({
            "policy": str(pol.get("policy", "")),
            "subpolicy": str(pol.get("subdomain_policy", "")),
            "pct": str(pol.get("percentage", "")),
        })
        for iid in _dmarc_issues(dmarc_records[0]):
            issues.append({"id": iid, "detail": f"DMARC record: {dmarc_records[0][:120]}"})

    # ── DKIM (selector brute + key strength) ──
    sel_results = await asyncio.gather(*(
        _hygiene_txt(f"{s}._domainkey.{host}", lifetime=4.0) for s in _DKIM_SELECTORS
    ))
    found: list[dict] = []
    definitive = 0
    for sel, (status, txts) in zip(_DKIM_SELECTORS, sel_results):
        if status == "error":
            continue
        definitive += 1
        recs = [r for r in txts if r.startswith("v=DKIM1")]
        if not recs:
            continue
        parsed = _dkim_parse(recs[0])
        kind, bits = ("unknown", None)
        if not parsed["empty_key"]:
            kind, bits = _spki_key_bits(parsed["key_b64"])
        found.append({"selector": sel, "key_kind": kind, "key_bits": bits})
        if parsed["empty_key"]:
            issues.append({
                "id": "dkim_empty_key",
                "detail": f"Selector '{sel}' published with an empty public key",
            })
        elif kind == "rsa":
            if bits < 1024:
                issues.append({
                    "id": "dkim_key_weak",
                    "detail": f"Selector '{sel}' RSA key is {bits} bits",
                })
            elif bits < 2048:
                issues.append({
                    "id": "dkim_key_legacy",
                    "detail": f"Selector '{sel}' RSA key is {bits} bits (2048+ recommended)",
                })
    dkim: dict = {"selectors_checked": len(_DKIM_SELECTORS), "found": found, "count": len(found)}
    if not found and definitive > 0:
        issues.append({
            "id": "dkim_missing",
            "detail": f"No DKIM key under {len(_DKIM_SELECTORS)} common selectors",
        })

    # ── DNSKEY (apex zone keys) ──
    dk_status, dk_keys = await _hygiene_dnskey(host)
    dnskey: dict = {"present": bool(dk_keys), "keys": []}
    if dk_status == "error":
        dnskey["status"] = "error"
    for k in dk_keys:
        bits = _dnskey_bits(k["algorithm"], k["publickey"])
        entry = dict(k)
        entry["key_bits"] = bits
        dnskey["keys"].append(entry)
        if bits is not None and bits < 2048:
            weak = bits < 1024
            issues.append({
                "id": "dnskey_weak" if weak else "dnskey_legacy",
                "detail": f"DNSKEY algorithm {k['algorithm']} key is {bits} bits",
            })

    return {
        "target": host,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "dnskey": dnskey,
        "issues": issues,
        "count": len(issues),
    }