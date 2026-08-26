"""Web Security tools — pure Python, no external binaries required."""
import asyncio
import re
import ssl
import socket
import time
import json
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import Any

import aiohttp

from backend.tools.osint import _is_ip


# ── 9. Header Analyzer ─────────────────────────────────────────
async def header_analyzer(url: str, **kw) -> dict:
    """HTTP security headers audit."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    security_headers = {
        "Strict-Transport-Security": {
            "description": "HSTS — forces HTTPS",
            "severity": "high",
            "recommendation": "max-age=31536000; includeSubDomains; preload",
        },
        "Content-Security-Policy": {
            "description": "CSP — prevents XSS and injection",
            "severity": "high",
            "recommendation": "default-src 'self'; script-src 'self'",
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME sniffing",
            "severity": "medium",
            "recommendation": "nosniff",
        },
        "X-Frame-Options": {
            "description": "Clickjacking protection",
            "severity": "medium",
            "recommendation": "DENY or SAMEORIGIN",
        },
        "X-XSS-Protection": {
            "description": "XSS filter (legacy)",
            "severity": "low",
            "recommendation": "1; mode=block",
        },
        "Referrer-Policy": {
            "description": "Controls referrer information",
            "severity": "low",
            "recommendation": "strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "description": "Feature permissions (camera, mic, etc.)",
            "severity": "medium",
            "recommendation": "camera=(), microphone=(), geolocation=()",
        },
        "Cross-Origin-Opener-Policy": {
            "description": "COOP — cross-origin isolation",
            "severity": "medium",
            "recommendation": "same-origin",
        },
        "Cross-Origin-Embedder-Policy": {
            "description": "COEP — prevents loading cross-origin resources",
            "severity": "low",
            "recommendation": "require-corp",
        },
        "Cross-Origin-Resource-Policy": {
            "description": "CORP — restricts resource loading",
            "severity": "low",
            "recommendation": "same-origin",
        },
    }

    # Headers to avoid (information leakage)
    bad_headers = {
        "Server": "Server version disclosure",
        "X-Powered-By": "Technology stack disclosure",
        "X-AspNet-Version": "ASP.NET version disclosure",
        "X-AspNetMvc-Version": "ASP.NET MVC version disclosure",
    }

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            async with session.get(url, allow_redirects=True) as resp:
                headers = dict(resp.headers)

                present = []
                missing = []
                score = 0
                max_score = len(security_headers)

                for hdr, info in security_headers.items():
                    if hdr in headers:
                        present.append({
                            "header": hdr,
                            "value": headers[hdr],
                            **info,
                        })
                        score += 1
                    else:
                        missing.append({"header": hdr, **info})

                leaked = []
                for hdr, desc in bad_headers.items():
                    if hdr in headers:
                        leaked.append({"header": hdr, "value": headers[hdr], "risk": desc})

                grade = "A+" if score >= 9 else "A" if score >= 7 else "B" if score >= 5 else "C" if score >= 3 else "D" if score >= 1 else "F"

                return {
                    "url": str(resp.url),
                    "status": resp.status,
                    "score": f"{score}/{max_score}",
                    "grade": grade,
                    "security_headers_present": present,
                    "security_headers_missing": missing,
                    "information_leakage": leaked,
                }
    except Exception as e:
        return {"url": url, "error": str(e)}


# ── 10. Directory Fuzzer ───────────────────────────────────────
async def dir_fuzzer(url: str, wordlist: str = "common", threads: int = 50, **kw) -> dict:
    """Web directory and file brute-force discovery."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    if not url.endswith("/"):
        url += "/"

    # Built-in wordlists
    words = {
        "common": [
            "admin", "login", "wp-admin", "wp-login.php", "administrator", "panel",
            "dashboard", "config", "backup", "bak", "old", "test", "dev", "staging",
            "api", "v1", "v2", "graphql", "swagger", "docs", "doc", "help", "support",
            "robots.txt", "sitemap.xml", ".env", ".git", ".svn", ".htaccess",
            "web.config", "crossdomain.xml", "favicon.ico", "info.php", "phpinfo.php",
            "server-status", "server-info", ".well-known", "security.txt",
            "wp-content", "wp-includes", "wp-json", "xmlrpc.php", "readme.html",
            "license.txt", "changelog.txt", "install", "setup", "upgrade", "update",
            "upload", "uploads", "images", "img", "css", "js", "static", "assets",
            "media", "files", "download", "downloads", "temp", "tmp", "cache",
            "log", "logs", "debug", "trace", "error", "errors", "404", "500",
            "cgi-bin", "bin", "scripts", "includes", "lib", "vendor", "node_modules",
            "package.json", "composer.json", "Gemfile", "requirements.txt",
            "Dockerfile", "docker-compose.yml", ".dockerenv", "Makefile",
            "admin.php", "login.php", "register", "signup", "signin", "auth",
            "user", "users", "account", "profile", "settings", "config.php",
            "database", "db", "sql", "dump", "backup.sql", "db.sql",
            "phpmyadmin", "adminer", "pma", "mysql", "postgres", "mongo",
            "redis", "memcached", "elasticsearch", "kibana", "grafana",
            "jenkins", "gitlab", "gitea", "bitbucket", "jira", "confluence",
            "monitoring", "status", "health", "ping", "metrics", "prometheus",
            "actuator", "env", "beans", "configprops", "mappings",
        ],
    }

    paths = words.get(wordlist, words["common"])
    found = []
    sem = asyncio.Semaphore(threads)

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=10),
        connector=aiohttp.TCPConnector(ssl=False, limit=threads)
    ) as session:
        async def check_path(path: str):
            async with sem:
                target = urljoin(url, path)
                try:
                    async with session.get(target, allow_redirects=False) as resp:
                        if resp.status not in (404, 405, 502, 503):
                            size = resp.content_length or 0
                            found.append({
                                "path": path,
                                "url": target,
                                "status": resp.status,
                                "size": size,
                                "content_type": resp.headers.get("Content-Type", ""),
                            })
                except Exception:
                    pass

        start = time.time()
        await asyncio.gather(*[check_path(w) for w in paths])
    elapsed = round(time.time() - start, 2)

    found.sort(key=lambda x: x["status"])
    return {
        "target": url,
        "found": found,
        "count": len(found),
        "wordlist_size": len(paths),
        "elapsed_seconds": elapsed,
    }


# ── 11. SQLi Scanner ───────────────────────────────────────────
async def sqli_scanner(url: str, **kw) -> dict:
    """Basic SQL injection detection via error-based tests."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Also detect forms in the page for POST testing
    post_params = {}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), connector=aiohttp.TCPConnector(ssl=False)) as detect_sess:
            async with detect_sess.get(url) as resp:
                body = await resp.text()
                import re
                forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.S | re.I)
                for form in forms:
                    inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form, re.I)
                    for inp in inputs:
                        post_params[inp] = "test"
    except Exception:
        pass

    if not params and not post_params:
        return {"url": url, "vulnerable": False, "reason": "No URL parameters or form fields found to test"}

    sqli_payloads = [
        ("'", "single quote"),
        ("\"", "double quote"),
        ("' OR '1'='1", "boolean OR"),
        ("\" OR \"1\"=\"1", "boolean OR double"),
        ("1' ORDER BY 100--", "order by"),
        ("' UNION SELECT NULL--", "union select"),
        ("1 AND 1=1", "numeric boolean true"),
        ("1 AND 1=2", "numeric boolean false"),
        ("'; WAITFOR DELAY '0:0:5'--", "time-based MSSQL"),
        ("1' AND SLEEP(5)--", "time-based MySQL"),
    ]

    sqli_errors = [
        "sql syntax", "mysql_fetch", "sqlite3", "postgresql", "ora-",
        "microsoft ole db", "unclosed quotation mark", "syntax error",
        "sql server", "odbc", "jdbc", "pg_query", "mysqli_",
        "you have an error in your sql", "warning: mysql",
        "valid mysql result", "mysqlclient", "sqlite_error",
        "sqlstate", "pg_exec", "pg_prepare", "division by zero",
        "supplied argument is not a valid", "column count doesn't match",
        "quoted string not properly terminated",
    ]

    findings = []
    base_resp = None

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            # Get baseline response
            async with session.get(url) as resp:
                base_text = await resp.text()
                base_status = resp.status
                base_len = len(base_text)

            # Test GET parameters
            for param_name in params:
                for payload, ptype in sqli_payloads:
                    test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                    try:
                        async with session.get(test_url, allow_redirects=False) as resp:
                            text = await resp.text()
                            text_lower = text.lower()

                            for error in sqli_errors:
                                if error in text_lower and error not in base_text.lower():
                                    findings.append({
                                        "parameter": param_name,
                                        "payload": payload,
                                        "type": "error-based",
                                        "payload_type": ptype,
                                        "evidence": error,
                                        "status": resp.status,
                                    })
                                    break

                            # Boolean-based detection
                            if ptype in ("numeric boolean true", "numeric boolean false"):
                                len_diff = abs(len(text) - base_len)
                                if len_diff > 100:
                                    findings.append({
                                        "parameter": param_name,
                                        "payload": payload,
                                        "type": "boolean-based",
                                        "payload_type": ptype,
                                        "evidence": f"Response length diff: {len_diff} bytes",
                                        "status": resp.status,
                                    })
                    except Exception:
                        pass

            # Test POST parameters (form fields)
            for param_name in post_params:
                for payload, ptype in sqli_payloads[:6]:  # Fewer payloads for POST
                    test_data = dict(post_params)
                    test_data[param_name] = payload
                    try:
                        async with session.post(url, data=test_data, allow_redirects=False) as resp:
                            text = await resp.text()
                            text_lower = text.lower()
                            for error in sqli_errors:
                                if error in text_lower and error not in base_text.lower():
                                    findings.append({
                                        "parameter": param_name,
                                        "payload": payload,
                                        "type": "error-based (POST)",
                                        "payload_type": ptype,
                                        "evidence": error,
                                        "status": resp.status,
                                    })
                                    break
                    except Exception:
                        pass

    except Exception as e:
        return {"url": url, "error": str(e)}

    # Deduplicate findings
    seen = set()
    unique = []
    for f in findings:
        key = f"{f['parameter']}-{f['type']}-{f['evidence']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {
        "url": url,
        "vulnerable": len(unique) > 0,
        "findings": unique,
        "finding_count": len(unique),
        "parameters_tested": list(params.keys()),
    }


# ── 12. XSS Scanner ───────────────────────────────────────────
async def xss_scanner(url: str, **kw) -> dict:
    """Reflected XSS detection in URL parameters."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return {"url": url, "vulnerable": False, "reason": "No URL parameters found"}

    xss_payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "';alert(1)//",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
    ]

    findings = []

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            for param_name in params:
                for payload in xss_payloads:
                    test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                    try:
                        async with session.get(test_url, allow_redirects=False) as resp:
                            text = await resp.text()
                            if payload in text:
                                findings.append({
                                    "parameter": param_name,
                                    "payload": payload,
                                    "type": "reflected",
                                    "status": resp.status,
                                })
                                break  # One finding per param is enough
                    except Exception:
                        pass
    except Exception as e:
        return {"url": url, "error": str(e)}

    return {
        "url": url,
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "finding_count": len(findings),
        "parameters_tested": list(params.keys()),
    }


# ── 13. CORS Checker ──────────────────────────────────────────
async def cors_checker(url: str, **kw) -> dict:
    """CORS misconfiguration detection."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    tests = [
        {"origin": "https://evil.com", "name": "arbitrary_origin"},
        {"origin": "null", "name": "null_origin"},
        {"origin": url.replace("https://", "http://"), "name": "http_downgrade"},
    ]

    # Also try subdomain reflection
    parsed = urlparse(url)
    parts = parsed.netloc.split(".")
    if len(parts) >= 2:
        tests.append({
            "origin": f"https://evil.{parts[-2]}.{parts[-1]}",
            "name": "subdomain_wildcard",
        })

    results = []

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            for test in tests:
                try:
                    headers = {"Origin": test["origin"]}
                    async with session.get(url, headers=headers, allow_redirects=False) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                        vulnerable = False
                        risk = "none"

                        if acao == test["origin"]:
                            if test["name"] == "arbitrary_origin":
                                vulnerable = True
                                risk = "critical" if acac.lower() == "true" else "high"
                            elif test["name"] == "null_origin":
                                vulnerable = True
                                risk = "high"
                            elif test["name"] == "subdomain_wildcard":
                                risk = "medium"

                        results.append({
                            "test": test["name"],
                            "origin_sent": test["origin"],
                            "acao": acao or "(not set)",
                            "acac": acac or "(not set)",
                            "vulnerable": vulnerable,
                            "risk": risk,
                        })
                except Exception:
                    results.append({"test": test["name"], "error": "request failed"})
    except Exception as e:
        return {"url": url, "error": str(e)}

    vulnerable_count = sum(1 for r in results if r.get("vulnerable"))
    return {
        "url": url,
        "tests": results,
        "vulnerable": vulnerable_count > 0,
        "vulnerable_count": vulnerable_count,
    }


# ── 14. Tech Detector ─────────────────────────────────────────
async def tech_detector(url: str, **kw) -> dict:
    """Web technology stack fingerprinting."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    signatures = {
        "CMS": {
            "WordPress": ["wp-content", "wp-includes", "wordpress", "wp-json"],
            "Joomla": ["joomla", "/administrator/", "com_content"],
            "Drupal": ["drupal", "sites/default/files", "misc/drupal.js"],
            "Shopify": ["shopify", "cdn.shopify.com"],
            "Wix": ["wix.com", "static.wixstatic.com"],
            "Squarespace": ["squarespace.com", "static.squarespace.com"],
            "Ghost": ["ghost-", "ghost.io", "content/themes"],
        },
        "Frameworks": {
            "React": ["react", "_reactRoot", "react.production.min.js", "__NEXT_DATA__"],
            "Vue.js": ["vue.js", "__vue__", "v-cloak", "nuxt"],
            "Angular": ["ng-version", "angular", "ng-app"],
            "Svelte": ["svelte", "__svelte"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "Tailwind": ["tailwindcss", "tailwind"],
            "Next.js": ["__NEXT_DATA__", "_next/static"],
            "Nuxt.js": ["__NUXT__", "_nuxt/"],
        },
        "Backend": {
            "Laravel": ["laravel", "csrf-token", "XSRF-TOKEN"],
            "Django": ["csrfmiddlewaretoken", "django", "admin/js/"],
            "Flask": ["werkzeug"],
            "Express": ["express", "X-Powered-By: Express"],
            "Ruby on Rails": ["csrf-token", "rails", "actioncable"],
            "Spring": ["spring", "jsessionid"],
            "ASP.NET": ["__viewstate", "asp.net", "x-aspnet"],
            "PHP": [".php"],
        },
        "Servers": {
            "nginx": ["nginx"],
            "Apache": ["apache", "mod_"],
            "IIS": ["microsoft-iis", "x-aspnet"],
            "Caddy": ["caddy"],
            "LiteSpeed": ["litespeed"],
        },
        "CDN": {
            "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status"],
            "AWS CloudFront": ["cloudfront", "x-amz-cf-id"],
            "Fastly": ["fastly", "x-served-by"],
            "Akamai": ["akamai", "x-akamai"],
        },
        "Analytics": {
            "Google Analytics": ["google-analytics", "googletagmanager", "gtag"],
            "Hotjar": ["hotjar"],
            "Matomo": ["matomo", "piwik"],
        },
    }

    detected = {}

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            async with session.get(url, allow_redirects=True) as resp:
                body = await resp.text()
                body_lower = body.lower()
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                headers_text = " ".join(f"{k}: {v}" for k, v in headers.items())

                combined = body_lower + " " + headers_text

                for category, techs in signatures.items():
                    for tech_name, sigs in techs.items():
                        for sig in sigs:
                            if sig.lower() in combined:
                                if category not in detected:
                                    detected[category] = []
                                if tech_name not in detected[category]:
                                    detected[category].append(tech_name)
                                break

                # Extract meta generator
                import re
                generator = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', body, re.I)
                if generator:
                    detected.setdefault("Meta", []).append(f"Generator: {generator.group(1)}")

                return {
                    "url": str(resp.url),
                    "status": resp.status,
                    "server": resp.headers.get("Server", "unknown"),
                    "technologies": detected,
                    "total_detected": sum(len(v) for v in detected.values()),
                }
    except Exception as e:
        return {"url": url, "error": str(e)}


# ── CVE Correlation (Fase 1 / F1-CVE) ─────────────────────────
KEV_FEED_URL = (
    "https://raw.githubusercontent.com/cisagov/known-exploited-vulnerabilities-feeds/"
    "main/CISA_KEV_Json_Feed.json"
)

# Tech name (as emitted by tech_detector) -> NVD keyword search term.
_NVD_SEARCH_TERMS = {
    "WordPress": "wordpress",
    "Joomla": "joomla",
    "Drupal": "drupal",
    "Laravel": "laravel",
    "Django": "django",
    "Flask": "flask python",
    "Express": "express node.js",
    "Ruby on Rails": "ruby on rails",
    "Spring": "spring framework",
    "ASP.NET": "asp.net",
    "PHP": "php",
    "nginx": "nginx",
    "Apache": "apache http server",
    "IIS": "internet information services",
}

_NVD_MAX_TECHS = 8
_NVD_MAX_CVES_PER_TECH = 5


def _extract_versions(server_header: str) -> dict:
    """Parse 'name/version' pairs out of an HTTP Server header."""
    out = {}
    for m in re.finditer(r"([A-Za-z][A-Za-z0-9_.\-]*)/(\d[\w.\-]*)", server_header or ""):
        name, version = m.group(1), m.group(2)
        if name.lower() not in ("unknown", "ok", "other"):
            out.setdefault(name, version)
    return out


async def _nvd_product_search(term: str) -> list[dict]:
    """Keyword search on NVD 2.0; returns normalized CVE dicts ([] on failure)."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=25)
        ) as session:
            async with session.get(url, params={
                "keywordSearch": term,
                "resultsPerPage": _NVD_MAX_CVES_PER_TECH * 4,
            }) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
    except Exception:
        return []

    first_word = term.lower().split()[0]
    out: list[dict] = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        metrics = cve_data.get("metrics", {})
        cvss_score, severity = None, None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")
                break
        desc_en = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        # Keep only CVEs that plausibly belong to the searched product.
        if first_word not in (desc_en or "").lower():
            continue
        out.append({
            "id": cve_data.get("id"),
            "description": desc_en[:200],
            "cvss_score": cvss_score,
            "severity": severity,
            "published": cve_data.get("published"),
        })
        if len(out) >= _NVD_MAX_CVES_PER_TECH:
            break
    return out


async def _fetch_kev() -> list[dict]:
    """CISA KEV feed entries ([] on failure — correlation still works)."""
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=25)
        ) as session:
            async with session.get(KEV_FEED_URL) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
    except Exception:
        return []
    return data.get("vulnerabilities", [])


async def cve_correlation(url: str, **kw) -> dict:
    """Correlate the detected web stack against NVD CVEs and CISA KEV.

    Runs tech_detector first, extracts versions from the Server header,
    searches NVD per detected product and flags anything in the Known
    Exploited Vulnerabilities catalog.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    tech_result = await tech_detector(url)
    if "error" in tech_result:
        return {"url": url, "error": tech_result["error"]}

    techs: dict = tech_result.get("technologies", {})
    flat = [t for cat, items in techs.items() if cat != "Meta" for t in items]
    versions = _extract_versions(tech_result.get("server", ""))

    search_terms: list[str] = []
    for name in flat:
        term = _NVD_SEARCH_TERMS.get(name)
        if term and term not in search_terms:
            search_terms.append(term)
    search_terms = search_terms[:_NVD_MAX_TECHS]

    nvd_results = await asyncio.gather(*(_nvd_product_search(t) for t in search_terms))

    cves: list[dict] = []
    seen: set[str] = set()
    for term, res in zip(search_terms, nvd_results):
        for cve in res:
            cid = cve.get("id")
            if not cid or cid in seen:
                continue
            seen.add(cid)
            cves.append({"tech": term, **cve})

    kev_entries = await _fetch_kev()
    kev_by_id = {e.get("cveID"): e for e in kev_entries}
    for cve in cves:
        cve["in_kev"] = cve.get("id") in kev_by_id

    kev_matches: list[dict] = []
    for term, _ in zip(search_terms, nvd_results):
        first_word = term.lower().split()[0]
        for e in kev_entries:
            if first_word in (e.get("vulnerability_name") or "").lower():
                kev_matches.append({
                    "tech": term,
                    "id": e.get("cveID"),
                    "vulnerability_name": e.get("vulnerability_name"),
                    "due_date": e.get("dueDate"),
                    "required_action": e.get("requiredAction"),
                })

    cves.sort(key=lambda c: (not c["in_kev"], -(c.get("cvss_score") or 0)))

    return {
        "url": str(tech_result.get("url", url)),
        "status": tech_result.get("status"),
        "server": tech_result.get("server"),
        "technologies": techs,
        "versions": versions,
        "cves": cves,
        "kev_matches": kev_matches,
        "count": len(cves),
    }


# ── 15. CSP Analyzer ──────────────────────────────────────────
async def csp_analyzer(url: str, **kw) -> dict:
    """Content Security Policy strength analysis."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            async with session.get(url, allow_redirects=True) as resp:
                csp = resp.headers.get("Content-Security-Policy", "")
                csp_report = resp.headers.get("Content-Security-Policy-Report-Only", "")

                if not csp and not csp_report:
                    return {
                        "url": str(resp.url),
                        "has_csp": False,
                        "grade": "F",
                        "issues": ["No CSP header found"],
                    }

                policy = csp or csp_report
                directives = {}
                for part in policy.split(";"):
                    part = part.strip()
                    if part:
                        tokens = part.split()
                        if tokens:
                            directives[tokens[0]] = tokens[1:]

                issues = []
                score = 0

                # Check for dangerous patterns
                for directive, sources in directives.items():
                    if "'unsafe-inline'" in sources:
                        issues.append(f" {directive}: 'unsafe-inline' weakens XSS protection")
                    if "'unsafe-eval'" in sources:
                        issues.append(f" {directive}: 'unsafe-eval' allows code injection")
                    if "*" in sources:
                        issues.append(f" {directive}: wildcard '*' allows any origin")
                    if "data:" in sources:
                        issues.append(f" {directive}: 'data:' URI can be exploited")
                    if "blob:" in sources:
                        issues.append(f" {directive}: 'blob:' URI may bypass restrictions")

                # Score
                important_directives = ["default-src", "script-src", "style-src", "img-src", "connect-src"]
                present = sum(1 for d in important_directives if d in directives)
                score = present * 20

                if "'unsafe-inline'" in str(directives.values()):
                    score -= 20
                if "'unsafe-eval'" in str(directives.values()):
                    score -= 20
                if "*" in str(directives.values()):
                    score -= 30

                score = max(0, min(100, score))
                grade = "A+" if score >= 90 else "A" if score >= 75 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F"

                return {
                    "url": str(resp.url),
                    "has_csp": True,
                    "is_report_only": bool(csp_report and not csp),
                    "policy": policy,
                    "directives": directives,
                    "issues": issues,
                    "score": score,
                    "grade": grade,
                }
    except Exception as e:
        return {"url": url, "error": str(e)}


# ── 16. Open Redirect ─────────────────────────────────────────
async def open_redirect(url: str, **kw) -> dict:
    """Open redirect vulnerability detection."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return {"url": url, "vulnerable": False, "reason": "No URL parameters found"}

    redirect_params = ["url", "redirect", "next", "return", "returnUrl", "returnTo",
                       "redirect_uri", "redirect_url", "go", "to", "out", "view",
                       "continue", "dest", "destination", "redir", "redirect_uri",
                       "forward", "target", "rurl", "dest_url", "u", "link", "href"]

    payloads = [
        "https://evil.com",
        "//evil.com",
        "https://evil.com%00.legit.com",
        "/\\evil.com",
        "https://legit.com@evil.com",
        "https://evil.com#legit.com",
    ]

    # Find redirect-like parameters
    test_params = []
    for param_name in params:
        if param_name.lower() in [r.lower() for r in redirect_params]:
            test_params.append(param_name)

    # Also test first parameter if none match
    if not test_params and params:
        test_params = list(params.keys())[:1]

    findings = []

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            for param_name in test_params:
                for payload in payloads:
                    test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    test_params_dict[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_dict)}"

                    try:
                        async with session.get(test_url, allow_redirects=False) as resp:
                            location = resp.headers.get("Location", "")
                            if resp.status in (301, 302, 303, 307, 308):
                                if "evil.com" in location:
                                    findings.append({
                                        "parameter": param_name,
                                        "payload": payload,
                                        "redirect_to": location,
                                        "status": resp.status,
                                    })
                                    break
                    except Exception:
                        pass
    except Exception as e:
        return {"url": url, "error": str(e)}

    return {
        "url": url,
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "finding_count": len(findings),
        "parameters_tested": test_params,
    }


# ── 16. Secret Leak Scanner ────────────────────────────────────
# Known-path scanning (MVP decision, see SEGUIMIENTO.md): fixed JS paths +
# /.git/HEAD + /robots.txt. No crawling: wp-content plugin/theme assets are
# not enumerable without a crawl and stay out of scope for now.
_SECRET_JS_PATHS = [
    "/main.js", "/app.js", "/bundle.js", "/vendor.js", "/common.js", "/site.js",
    "/scripts/main.js", "/scripts/app.js", "/scripts/bundle.js",
    "/js/main.js", "/js/app.js", "/js/bundle.js",
    "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
    "/assets/js/main.js", "/assets/js/app.js", "/assets/js/bundle.js",
]
_GIT_EVIDENCE_PATHS = ["/.git/HEAD", "/.git/config", "/.git/logs/HEAD"]

# TruffleHog-style, high-confidence patterns only (no external deps).
# Each entry: (finding_type, tier, compiled regex). Tiers:
#   high   -> platform-specific keys (AWS/GitHub/Slack/Stripe/Google/private)
#   medium -> generic token-like assignments in JS/robots.txt
#   low    -> weak matches (password-ish assignments)
_SECRET_PATTERNS = [
    ("aws_access_key_id", "high", re.compile(r"(?i)\b(?:AKIA|ASIA|A3TQ)[A-Z0-9]{16}\b")),
    ("github_token", "high", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{14,255}|\bgithub_pat_[0-9A-Za-z]{14,255}\b")),
    ("slack_token", "high", re.compile(r"\bxox[baprs]-\d{1,}-[A-Za-z0-9\-]{8,}\b")),
    ("stripe_key", "high", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b|\bwhsec_[0-9A-Za-z]{16,}\b")),
    ("google_api_key", "high", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("private_key", "high", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")),
    ("generic_token", "medium", re.compile(
        r"""(?i)\b(api[_-]?key|apikey|auth[_-]?token|access[_-]?token|client[_-]?secret|"""
        r"""secret[_-]?key|private[_-]?key|session[_-]?token)\b\s*[:=]\s*["'][0-9A-Za-z_\-]{16,}["']""")),
    ("weak_match", "low", re.compile(
        r"""(?i)\b(password|passwd|pwd|db_pass)\b\s*[:=]\s*["'][^"']{8,}["']""")),
]


def _redact(value: str) -> str:
    """Keep just enough of a match to identify it without storing the secret."""
    v = value.strip()
    if len(v) <= 6:
        return "***"
    return f"{v[:4]}***({len(v)})"


def _scan_text(text: str, source: str, findings: list[dict]) -> None:
    """Scan one fetched document against the pattern table (first match wins)."""
    for ftype, tier, rx in _SECRET_PATTERNS:
        m = rx.search(text)
        if m:
            findings.append({
                "source": source,
                "type": ftype,
                "tier": tier,
                "evidence": _redact(m.group(0)),
            })
            return


async def _secret_fetch(url: str, timeout: float = 8.0) -> tuple[int | None, str]:
    """GET one URL; (status, body). Unreachable hosts yield (None, "")."""
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            async with session.get(url, allow_redirects=True) as resp:
                return resp.status, (await resp.text(errors="ignore"))
    except Exception:
        return None, ""


async def secret_leak_scan(target: str, **kw) -> dict:
    """Scan a web target for exposed secrets (known-path MVP).

    Fetches a fixed list of likely JS bundles, /.git/HEAD (plus config and
    logs/HEAD as extra evidence when the repo is exposed) and /robots.txt,
    then runs high-confidence TruffleHog-style patterns over the content.
    Unreachable URLs degrade to "not found"; they never break the scan.
    """
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    parsed = urlparse(target)
    host = (parsed.netloc or target).split("/")[0].split(":")[0].strip().lower()
    if not host or _is_ip(host):
        return {"target": host, "error": "Secret scan requires a domain, not an IP"}

    js_urls = [f"{parsed.scheme}://{host}{p}" for p in _SECRET_JS_PATHS]
    robots_url = f"{parsed.scheme}://{host}/robots.txt"
    git_urls = [f"{parsed.scheme}://{host}{p}" for p in _GIT_EVIDENCE_PATHS]

    fetched = await asyncio.gather(
        *(_secret_fetch(u) for u in js_urls + [robots_url] + git_urls)
    )
    js_results = fetched[:len(js_urls)]
    r_status, r_body = fetched[len(js_urls)]
    git_results = fetched[len(js_urls) + 1:]

    findings: list[dict] = []
    for url, (status, body) in zip(js_urls, js_results):
        if status == 200 and body:
            _scan_text(body, url, findings)
    if r_status == 200 and r_body:
        _scan_text(r_body, robots_url, findings)

    git_exposed = [p for p, (status, _body) in zip(_GIT_EVIDENCE_PATHS, git_results)
                   if status == 200]

    return {
        "target": host,
        "js_urls_checked": len(js_urls),
        "robots_checked": r_status == 200,
        "git_exposed_paths": git_exposed,
        "findings": findings,
        "count": len(findings) + len(git_exposed),
    }
