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

    if not params:
        return {"url": url, "vulnerable": False, "reason": "No URL parameters found to test"}

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
