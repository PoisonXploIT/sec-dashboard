"""Vulnerability tools — pure Python, no external binaries required."""
import asyncio
import hashlib
import json
import re
import time
from urllib.parse import urlparse

import aiohttp


# ── 17. CVE Search ─────────────────────────────────────────────
async def cve_search(query: str, max_results: int = 10, **kw) -> dict:
    """Search NIST NVD for CVEs by keyword or ID."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # If it looks like a CVE ID
    if re.match(r"CVE-\d{4}-\d+", query.upper()):
        params = {"cveId": query.upper()}
    else:
        params = {"keywordSearch": query, "resultsPerPage": max_results}

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=20)
        ) as session:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    cves = []
                    for vuln in data.get("vulnerabilities", [])[:max_results]:
                        cve_data = vuln.get("cve", {})
                        metrics = cve_data.get("metrics", {})

                        # Extract CVSS score
                        cvss_score = None
                        severity = None
                        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                            metric_list = metrics.get(metric_key, [])
                            if metric_list:
                                cvss_data = metric_list[0].get("cvssData", {})
                                cvss_score = cvss_data.get("baseScore")
                                severity = cvss_data.get("baseSeverity")
                                break

                        descriptions = cve_data.get("descriptions", [])
                        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                        cves.append({
                            "id": cve_data.get("id"),
                            "description": desc_en[:200],
                            "cvss_score": cvss_score,
                            "severity": severity,
                            "published": cve_data.get("published"),
                            "last_modified": cve_data.get("lastModified"),
                        })

                    return {
                        "query": query,
                        "total_results": data.get("totalResults", 0),
                        "cves": cves,
                        "count": len(cves),
                    }
                elif resp.status == 403:
                    return {"query": query, "error": "NVD API rate limit exceeded. Try again later."}
                else:
                    return {"query": query, "error": f"API returned status {resp.status}"}
    except Exception as e:
        return {"query": query, "error": str(e)}


# ── 18. Hash Lookup ───────────────────────────────────────────
async def hash_checker(hash_value: str, **kw) -> dict:
    """File hash reputation check via public APIs."""
    hash_value = hash_value.strip().lower()

    # Detect hash type
    if len(hash_value) == 32:
        hash_type = "MD5"
    elif len(hash_value) == 40:
        hash_type = "SHA-1"
    elif len(hash_value) == 64:
        hash_type = "SHA-256"
    else:
        return {"hash": hash_value, "error": "Unknown hash format (expected MD5/SHA1/SHA256)"}

    results = {"hash": hash_value, "hash_type": hash_type, "sources": {}}

    # Try MalwareBazaar (abuse.ch) — free, no key
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15)
        ) as session:
            mb_url = "https://mb-api.abuse.ch/api/v1/"
            data = {"query": "get_info", hash_type: hash_value}
            async with session.post(mb_url, data=data) as resp:
                if resp.status == 200:
                    mb_data = await resp.json(content_type=None)
                    if mb_data.get("query_status") == "hash_not_found":
                        results["sources"]["MalwareBazaar"] = {"found": False}
                    else:
                        results["sources"]["MalwareBazaar"] = {
                            "found": True,
                            "data": mb_data.get("data", [{}])[0] if mb_data.get("data") else {},
                        }
    except Exception:
        results["sources"]["MalwareBazaar"] = {"error": "request failed"}

    # Try VirusTotal (free API key, skip if no key)
    import os
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if vt_key:
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15)
            ) as session:
                vt_url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
                headers = {"x-apikey": vt_key}
                async with session.get(vt_url, headers=headers) as resp:
                    if resp.status == 200:
                        vt_data = await resp.json()
                        attrs = vt_data.get("data", {}).get("attributes", {})
                        results["sources"]["VirusTotal"] = {
                            "found": True,
                            "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                            "total_engines": sum(attrs.get("last_analysis_stats", {}).values()),
                            "reputation": attrs.get("reputation"),
                        }
                    elif resp.status == 404:
                        results["sources"]["VirusTotal"] = {"found": False}
        except Exception:
            results["sources"]["VirusTotal"] = {"error": "request failed"}

    if not results["sources"]:
        results["sources"]["note"] = "No API keys configured. Set VIRUSTOTAL_API_KEY for VirusTotal integration."

    return results


# ── 19. Password Audit ────────────────────────────────────────
async def password_audit(target: str = "", password: str = "", **kw) -> dict:
    """Password strength analysis and breach check."""
    # Accept password from either 'target' (first positional) or 'password' kwarg
    pwd = password or target
    if not pwd:
        return {"error": "No password provided", "hint": "Send a password parameter to analyze"}

    analysis = {
        "length": len(pwd),
        "has_uppercase": bool(re.search(r"[A-Z]", pwd)),
        "has_lowercase": bool(re.search(r"[a-z]", pwd)),
        "has_digits": bool(re.search(r"\d", pwd)),
        "has_special": bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", pwd)),
        "is_common": False,
        "entropy": 0,
    }

    # Calculate entropy
    charset_size = 0
    if analysis["has_lowercase"]: charset_size += 26
    if analysis["has_uppercase"]: charset_size += 26
    if analysis["has_digits"]: charset_size += 10
    if analysis["has_special"]: charset_size += 32

    if charset_size > 0 and len(pwd) > 0:
        import math
        analysis["entropy"] = round(len(pwd) * math.log2(charset_size), 1)

    # Check common passwords
    common_passwords = [
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
        "dragon", "letmein", "login", "princess", "football", "shadow", "sunshine",
        "trustno1", "iloveyou", "batman", "access", "hello", "charlie", "donald",
        "password1", "password123", "admin", "root", "toor", "pass", "test",
        "guest", "changeme", "default", "welcome", "1234", "12345", "123456789",
    ]
    analysis["is_common"] = pwd.lower() in common_passwords

    # Check Have I Been Pwned (k-anonymity API)
    pwned = None
    try:
        sha1 = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10)
        ) as session:
            async with session.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"}
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.split("\n"):
                        parts = line.strip().split(":")
                        if len(parts) == 2 and parts[0] == suffix:
                            pwned = int(parts[1])
                            break
                    if pwned is None:
                        pwned = 0
    except Exception:
        pass

    # Score
    score = 0
    if analysis["length"] >= 8: score += 1
    if analysis["length"] >= 12: score += 1
    if analysis["length"] >= 16: score += 1
    if analysis["has_uppercase"]: score += 1
    if analysis["has_lowercase"]: score += 1
    if analysis["has_digits"]: score += 1
    if analysis["has_special"]: score += 1
    if analysis["entropy"] >= 40: score += 1
    if analysis["entropy"] >= 60: score += 1
    if not analysis["is_common"]: score += 1
    if pwned == 0: score += 1

    strength = "Critical" if score <= 2 else "Weak" if score <= 4 else "Fair" if score <= 6 else "Strong" if score <= 8 else "Excellent"

    return {
        "strength": strength,
        "score": f"{score}/11",
        "analysis": analysis,
        "breached_count": pwned,
        "breached": pwned > 0 if pwned is not None else None,
        "recommendations": _password_recommendations(analysis, pwned),
    }


def _password_recommendations(analysis: dict, pwned: int | None) -> list:
    recs = []
    if analysis["length"] < 12:
        recs.append("Use at least 12 characters")
    if not analysis["has_uppercase"]:
        recs.append("Add uppercase letters")
    if not analysis["has_lowercase"]:
        recs.append("Add lowercase letters")
    if not analysis["has_digits"]:
        recs.append("Add numbers")
    if not analysis["has_special"]:
        recs.append("Add special characters (!@#$%...)")
    if analysis["is_common"]:
        recs.append("❌ This is a commonly used password — avoid it!")
    if pwned and pwned > 0:
        recs.append(f"❌ Found in {pwned:,} data breaches — do NOT use!")
    return recs
