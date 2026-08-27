"""OSINT tools -- passive reconnaissance, no packets to target."""
import asyncio
import json
import os
import re
import socket
from urllib.parse import urlparse

import aiohttp

from backend.proxy import get_aiohttp_connector


# -- 1. IP/ASN Lookup (bgpview.io - free, no key) ----------------
async def asn_lookup(target: str, **kw) -> dict:
    """ASN and BGP information for an IP or domain."""
    # Resolve domain to IP if needed
    ip = target
    if not _is_ip(target):
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, target)
        except socket.gaierror:
            return {"target": target, "error": "Could not resolve domain"}

    results = {"target": target, "ip": ip, "sources": {}}

    # bgpview.io - free API, no key
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), connector=get_aiohttp_connector()) as session:
            async with session.get(f"https://api.bgpview.io/ip/{ip}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ip_data = data.get("data", {})
                    results["sources"]["bgpview"] = {
                        "ip": ip_data.get("ip"),
                        "prefix": ip_data.get("prefixes", [{}])[0].get("prefix", "") if ip_data.get("prefixes") else "",
                        "asn": ip_data.get("prefixes", [{}])[0].get("asn", {}).get("asn", "") if ip_data.get("prefixes") else "",
                        "name": ip_data.get("prefixes", [{}])[0].get("name", "") if ip_data.get("prefixes") else "",
                        "description": ip_data.get("prefixes", [{}])[0].get("description", "") if ip_data.get("prefixes") else "",
                        "country_code": ip_data.get("prefixes", [{}])[0].get("country_code", "") if ip_data.get("prefixes") else "",
                        "rir_name": ip_data.get("rir_name", ""),
                    }
                elif resp.status == 429:
                    results["sources"]["bgpview"] = {"error": "Rate limited"}
    except Exception as e:
        results["sources"]["bgpview"] = {"error": str(e)[:80]}

    # Fallback: use ip-api.com ASN data (already works without bgpview)
    if not results["sources"].get("bgpview") or results["sources"]["bgpview"].get("error"):
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), connector=get_aiohttp_connector()) as session:
                async with session.get(f"http://ip-api.com/json/{ip}?fields=status,country,as,asname,isp,org,query") as resp:
                    if resp.status == 200:
                        ipdata = await resp.json()
                        if ipdata.get("status") == "success":
                            as_str = ipdata.get("as", "")
                            # Parse "AS13335 Cloudflare, Inc."
                            asn_num = ""
                            if as_str.startswith("AS"):
                                parts = as_str.split(" ", 1)
                                asn_num = parts[0].replace("AS", "")
                                as_name = parts[1] if len(parts) > 1 else ""
                            else:
                                as_name = as_str
                            results["sources"]["ip_api"] = {
                                "asn": asn_num,
                                "name": as_name,
                                "country": ipdata.get("country", ""),
                                "isp": ipdata.get("isp", ""),
                                "org": ipdata.get("org", ""),
                            }
                            # If we got ASN from ip-api, try bgpview for more details
                            if asn_num and not results.get("asn_details"):
                                try:
                                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), connector=get_aiohttp_connector()) as session2:
                                        async with session2.get(f"https://api.bgpview.io/asn/{asn_num}") as resp2:
                                            if resp2.status == 200:
                                                asn_data = (await resp2.json()).get("data", {})
                                                results["asn_details"] = {
                                                    "asn": asn_num,
                                                    "name": asn_data.get("name", as_name),
                                                    "description": asn_data.get("description_short", ""),
                                                    "country": asn_data.get("country_code", ""),
                                                    "website": asn_data.get("website", ""),
                                                }
                                except Exception:
                                    pass
        except Exception as e:
            results["sources"]["ip_api"] = {"error": str(e)[:80]}

    return results


# -- 2. Reverse DNS + PTR chain ----------------------------------
async def reverse_dns(target: str, **kw) -> dict:
    """Reverse DNS lookup and PTR chain for an IP or domain."""
    ip = target
    if not _is_ip(target):
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, target)
        except socket.gaierror:
            return {"target": target, "error": "Could not resolve"}

    results = {"target": target, "ip": ip, "ptr_records": [], "shared_domains": []}

    # PTR lookup
    try:
        hostname = await asyncio.to_thread(socket.gethostbyaddr, ip)
        results["ptr_records"] = list(hostname[1]) if len(hostname) > 1 else [hostname[0]]
        results["primary_ptr"] = hostname[0]
    except (socket.herror, socket.gaierror):
        results["primary_ptr"] = None

    # Check if IP resolves to multiple domains (shared hosting indicator)
    try:
        import dns.resolver
        # Reverse DNS via DNS
        reversed_ip = ".".join(reversed(ip.split(".")))
        try:
            answers = await asyncio.to_thread(
                dns.resolver.resolve, f"{reversed_ip}.in-addr.arpa", "PTR", lifetime=5
            )
            for rdata in answers:
                if str(rdata) not in results["ptr_records"]:
                    results["ptr_records"].append(str(rdata).rstrip("."))
        except Exception:
            pass
    except ImportError:
        pass

    return results


# -- 3. Certificate Transparency ----------------------------------
async def ct_logs(target: str, **kw) -> dict:
    """Certificate Transparency log search -- discovers subdomains via certs."""
    domain = target
    if _is_ip(target):
        return {"target": target, "error": "CT logs require a domain, not an IP"}

    results = {"target": domain, "subdomains": [], "cert_count": 0}

    # crt.sh - free CT log search
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20), connector=get_aiohttp_connector()) as session:
            async with session.get(f"https://crt.sh/?q=%.{domain}&output=json") as resp:
                if resp.status == 200:
                    certs = await resp.json(content_type=None)
                    seen = set()
                    for cert in certs:
                        name = cert.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub and sub.endswith(domain) and sub not in seen and "*" not in sub:
                                seen.add(sub)
                    results["subdomains"] = sorted(seen)
                    results["cert_count"] = len(certs)
                    results["unique_subdomains"] = len(seen)
    except Exception as e:
        results["error"] = str(e)[:80]

    return results


# -- 4. Shodan (free InternetDB + optional API key) -----------------

_SHODAN_DSEARCH_URL = "https://api.shodan.io/shodan/dsearch"
_SHODAN_HOST_URL = "https://api.shodan.io/shodan/host"
_SHODAN_FIELDS = "port,product,version,banner,vulns,tags,cpe,os,hostnames"
_SHODAN_MAX_RESULTS = 100


async def _shodan_query(ip: str, key: str) -> dict | None:
    """One dsearch query for an IP; returns the parsed JSON.

    None means the query itself failed (network/HTTP/JSON); the caller
    must treat it as best-effort and fall back to /host.
    """
    params = {
        "query": ip,
        "key": key,
        "min": "0",
        "max": str(_SHODAN_MAX_RESULTS),
        "fields": _SHODAN_FIELDS,
    }
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15)
        ) as session:
            async with session.get(_SHODAN_DSEARCH_URL, params=params) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


async def _shodan_host_query(ip: str, key: str) -> dict | None:
    """One /host lookup for an IP; returns the parsed JSON.

    None means the query itself failed (network/HTTP/JSON).
    """
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15)
        ) as session:
            async with session.get(f"{_SHODAN_HOST_URL}/{ip}", params={"key": key}) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


async def shodan_lookup(target: str, **kw) -> dict:
    """Shodan internet intelligence lookup.

    Without SHODAN_API_KEY: free InternetDB (no key). With the key:
    dsearch query API (banners, vulns, tags), falling back to /host if
    dsearch is empty or fails. Best-effort throughout.
    """
    ip = target
    if not _is_ip(target):
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, target)
        except socket.gaierror:
            return {"target": target, "error": "Could not resolve"}

    shodan_key = os.environ.get("SHODAN_API_KEY", "")

    if not shodan_key:
        # Free tier: internetdb.shodan.io (no key needed)
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), connector=get_aiohttp_connector()) as session:
                async with session.get(f"https://internetdb.shodan.io/{ip}") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "target": target,
                            "ip": ip,
                            "source": "shodan_internetdb",
                            "ports": data.get("ports", []),
                            "cpes": data.get("cpes", []),
                            "vulns": data.get("vulns", []),
                            "hostnames": data.get("hostnames", []),
                            "os": data.get("os"),
                            "tags": data.get("tags", []),
                        }
                    elif resp.status == 404:
                        return {"target": target, "ip": ip, "source": "shodan_internetdb", "error": "IP not found in Shodan"}
        except Exception as e:
            return {"target": target, "ip": ip, "source": "shodan_internetdb", "error": str(e)[:80]}

    data = await _shodan_query(ip, shodan_key)
    rows: list[dict] = []
    if isinstance(data, dict):
        for r in data.get("result_set") or []:
            if not isinstance(r, dict):
                continue
            rows.append({
                "port": r.get("port"),
                "product": r.get("product", ""),
                "version": r.get("version", ""),
                "banner": (r.get("banner") or "")[:500],
                "vulns": [str(v) for v in r.get("vulns") or [] if isinstance(v, str)],
                "tags": r.get("tags") or [],
                "cpe": r.get("cpe", ""),
                "os": r.get("os", ""),
                "hostnames": r.get("hostnames") or [],
            })
    if rows:
        return {
            "target": target,
            "ip": ip,
            "source": "shodan_dsearch",
            "total": data.get("total"),
            "count": len(rows),
            "results": rows,
        }

    # dsearch empty or failed: fall back to /host.
    host_data = await _shodan_host_query(ip, shodan_key)
    if isinstance(host_data, dict):
        return {
            "target": target,
            "ip": ip,
            "source": "shodan_api",
            "ports": host_data.get("ports", []),
            "vulns": host_data.get("vulns", []),
            "os": host_data.get("os"),
            "org": host_data.get("org", ""),
            "isp": host_data.get("isp", ""),
            "hostnames": host_data.get("hostnames", []),
            "services": [
                {"port": s.get("port"), "transport": s.get("transport"), "product": s.get("product", ""), "version": s.get("version", "")}
                for s in (host_data.get("data") or [])[:20] if isinstance(s, dict)
            ],
        }

    return {"target": target, "ip": ip, "error": "No results"}


# -- 5. IP Geolocation (free) -------------------------------------
async def ip_geolocation(target: str, **kw) -> dict:
    """IP geolocation via free APIs."""
    ip = target
    if not _is_ip(target):
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, target)
        except socket.gaierror:
            return {"target": target, "error": "Could not resolve"}

    results = {"target": target, "ip": ip, "sources": {}}

    # ip-api.com (free, no key)
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), connector=get_aiohttp_connector()) as session:
            async with session.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        results["sources"]["ip-api"] = {
                            "country": data.get("country", ""),
                            "country_code": data.get("countryCode", ""),
                            "region": data.get("regionName", ""),
                            "city": data.get("city", ""),
                            "lat": data.get("lat"),
                            "lon": data.get("lon"),
                            "timezone": data.get("timezone", ""),
                            "isp": data.get("isp", ""),
                            "org": data.get("org", ""),
                            "as": data.get("as", ""),
                            "asname": data.get("asname", ""),
                            "reverse": data.get("reverse", ""),
                            "is_mobile": data.get("mobile", False),
                            "is_proxy": data.get("proxy", False),
                            "is_hosting": data.get("hosting", False),
                        }
    except Exception as e:
        results["sources"]["ip-api"] = {"error": str(e)[:80]}

    return results


# -- Helpers ------------------------------------------------------
def _is_ip(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except socket.error:
        return False


# ── PublicWWW Search (OSINT / publicwww.com) ───────────────────
_PUBLICWWW_API_URL = "https://api.publicwww.com/domains/"
_PUBLICWWW_MAX_ROWS = 1000


async def _publicwww_query(domain: str) -> list[dict] | None:
    """One GET to the publicwww API; returns raw rows.

    None means the query itself failed (network/HTTP/JSON); the caller
    must treat it as best-effort and degrade to an error dict.
    """
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60)
        ) as session:
            async with session.get(
                f"{_PUBLICWWW_API_URL}{domain}",
                headers={"User-Agent": "sec-dashboard"},
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    rows = data.get("rows")
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)][: _PUBLICWWW_MAX_ROWS]


async def publicwww_search(target: str, **kw) -> dict:
    """Exposed URLs/hosts of a domain via publicwww.com (passive).

    PublicWWW indexes the public web and reports every URL it has seen
    for the domain — attack-surface discovery (stale hosts, forgotten
    panels, tech stack). Best-effort: any failure degrades to an error dict.
    """
    t = target.strip().lower()
    if t.startswith(("http://", "https://")):
        t = re.sub(r"^https?://", "", t)
    host = t.split("/")[0].split(":")[0].strip()
    if not host or _is_ip(host):
        return {"target": host, "error": "publicwww_search requires a domain, not an IP"}

    rows = await _publicwww_query(host)
    if rows is None:
        return {"target": host, "error": "PublicWWW API unavailable or returned an error"}

    hosts: dict[str, None] = {}
    techs: dict[str, None] = {}
    urls: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        h = r.get("hostname")
        if isinstance(h, str) and h.strip():
            hosts.setdefault(h.strip())
        tech = r.get("tech")
        if isinstance(tech, dict):
            name = tech.get("name")
            if isinstance(name, str) and name:
                techs.setdefault(name)
        u = r.get("url")
        if isinstance(u, str) and u.strip():
            urls.append(u.strip())

    return {
        "target": host,
        "count": len(rows),
        "hosts": sorted(hosts)[:_PUBLICWWW_MAX_ROWS],
        "technologies": sorted(techs)[:100],
        "urls": urls[:200],
    }


# ── URLScan Lookup (OSINT / urlscan.io) ───────────────────────
_URLSCAN_API_URL = "https://urlscan.io/api/v1/search/"
_URLSCAN_MAX_ROWS = 1000


async def _urlscan_query(domain: str) -> list[dict] | None:
    """One GET to the urlscan.io search API; returns raw result rows.

    Anonymous (no key) search does NOT accept the `limit` param (400), so it
    is never sent. None means the query itself failed (network/HTTP/JSON);
    the caller must treat it as best-effort and degrade to an error dict.
    """
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60)
        ) as session:
            async with session.get(
                _URLSCAN_API_URL,
                params={"q": f"domain:{domain}"},
                headers={"User-Agent": "sec-dashboard"},
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    rows = data.get("results")
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)][: _URLSCAN_MAX_ROWS]


async def urlscan_lookup(target: str, **kw) -> dict:
    """Passive scan data of a domain via urlscan.io (no key).

    Searches the public urlscan.io corpus for every scan seen against the
    domain and its subdomains — attack-surface discovery (stale hosts,
    forgotten panels). Best-effort: any failure degrades to an error dict.
    """
    t = target.strip().lower()
    if t.startswith(("http://", "https://")):
        t = re.sub(r"^https?://", "", t)
    host = t.split("/")[0].split(":")[0].strip()
    if not host or _is_ip(host):
        return {"target": host, "error": "urlscan_lookup requires a domain, not an IP"}

    rows = await _urlscan_query(host)
    if rows is None:
        return {"target": host, "error": "URLScan API unavailable or returned an error"}

    hosts: dict[str, None] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        task = r.get("task")
        if isinstance(task, dict):
            d = task.get("domain")
            if isinstance(d, str) and d.strip():
                hosts.setdefault(d.strip())
        # canonical.task.url is the scanned host (canonical.page.url can be
        # a post-redirect path like "github.com/login" — not a host).
        canonical = r.get("canonical")
        if isinstance(canonical, dict):
            c = canonical.get("task")
            if isinstance(c, dict):
                u = c.get("url")
                if isinstance(u, str) and u.strip():
                    hosts.setdefault(u.strip())

    return {
        "target": host,
        "count": len(rows),
        "hosts": sorted(hosts)[:_URLSCAN_MAX_ROWS],
    }


# ── GreyNoise Community (OSINT / api.greynoise.io) ─────────────
_GREYNOISE_API_URL = "https://api.greynoise.io/v3/community/"


async def _greynoise_query(ip: str, key: str) -> dict | None:
    """One community lookup for an IP; returns the parsed JSON body.

    The Community API is public (works without a key, ~25 req/min);
    passing GREYNOISE_API_KEY via the `key` header raises the limit.
    404 (no data) is a valid answer and is returned as its JSON body.
    None means the query itself failed (network/HTTP/JSON); the caller
    must treat it as best-effort and degrade to an error dict.
    """
    headers = {"User-Agent": "sec-dashboard"}
    if key:
        headers["key"] = key
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15)
        ) as session:
            async with session.get(f"{_GREYNOISE_API_URL}{ip}", headers=headers) as resp:
                data = await resp.json()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


async def greynoise_lookup(target: str, **kw) -> dict:
    """GreyNoise community lookup: is this IP a known scanner?

    Works without GREYNOISE_API_KEY (public community endpoint); the key
    raises the rate limit. Best-effort: any failure degrades to an error
    dict.
    """
    ip = target
    if not _is_ip(target):
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, target)
        except socket.gaierror:
            return {"target": target, "error": "Could not resolve"}

    key = os.environ.get("GREYNOISE_API_KEY", "")
    data = await _greynoise_query(ip, key)
    if data is None:
        return {"target": target, "ip": ip,
                "error": "GreyNoise API unavailable or returned an error"}
    if "noise" not in data and "riot" not in data:
        # 400 invalid IP / 401 bad key / 429 rate limit body
        return {"target": target, "ip": ip,
                "error": str(data.get("message", "GreyNoise API error"))[:120]}

    noise = bool(data.get("noise"))
    riot = bool(data.get("riot"))
    if not (noise or riot):
        return {
            "target": target,
            "ip": ip,
            "found": False,
            "message": data.get("message", "IP not observed scanning the internet."),
        }

    return {
        "target": target,
        "ip": ip,
        "found": True,
        "noise": noise,
        "riot": riot,
        "classification": data.get("classification") or "",
        "name": data.get("name") or "",
        "last_seen": data.get("last_seen") or "",
    }


# ── Hunter Domain Search (OSINT / api.hunter.io) ────────────────
_HUNTER_API_URL = "https://api.hunter.io/v2/domain-search"
_HUNTER_MAX_ROWS = 100


async def _hunter_query(domain: str, key: str) -> list[dict] | None:
    """One GET to Hunter domain-search; returns raw email rows.

    None means the query itself failed (network/HTTP/JSON/auth); the
    caller must treat it as best-effort and degrade to an error dict.
    """
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            async with session.get(
                _HUNTER_API_URL,
                params={"domain": domain},
                headers={
                    "Authorization": f"Bearer {key}",
                    "User-Agent": "sec-dashboard",
                },
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    payload = data.get("data")
    rows = payload.get("emails") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)]


async def hunter_email_finder(target: str, **kw) -> dict:
    """Known email addresses of a domain via Hunter (HUNTER_API_KEY).

    Domain Search returns every email Hunter has seen on the domain with
    confidence scores and identity context — exposure surface for
    phishing and credential stuffing. No key: clean error dict, no
    network call. Free plan caps results at 10 per call.
    """
    t = target.strip().lower()
    if t.startswith(("http://", "https://")):
        t = re.sub(r"^https?://", "", t)
    host = t.split("/")[0].split(":")[0].strip()
    if not host or _is_ip(host):
        return {"target": host, "error": "hunter_email_finder requires a domain, not an IP"}

    key = os.environ.get("HUNTER_API_KEY", "")
    if not key:
        return {"target": host, "error": "HUNTER_API_KEY not set (free key at hunter.io/api)"}

    rows = await _hunter_query(host, key)
    if rows is None:
        return {"target": host, "error": "Hunter API unavailable or returned an error"}

    emails: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        value = r.get("value")
        if not isinstance(value, str) or not value.strip():
            continue
        v = value.strip().lower()
        if v in seen:
            continue
        seen.add(v)
        emails.append({
            "email": v,
            "confidence": r.get("confidence"),
            "type": r.get("type") or "",
            "first_name": r.get("first_name") or "",
            "last_name": r.get("last_name") or "",
            "position": r.get("position") or "",
            "decision_maker": bool(r.get("decision_maker")),
        })

    emails = emails[:_HUNTER_MAX_ROWS]
    return {"target": host, "count": len(emails), "emails": emails}
