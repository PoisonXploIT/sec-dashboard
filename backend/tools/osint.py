"""OSINT tools -- passive reconnaissance, no packets to target."""
import asyncio
import json
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

    # ASN prefix info
    asn_num = results.get("sources", {}).get("bgpview", {}).get("asn", "")
    if asn_num:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), connector=get_aiohttp_connector()) as session:
                async with session.get(f"https://api.bgpview.io/asn/{asn_num}") as resp:
                    if resp.status == 200:
                        asn_data = (await resp.json()).get("data", {})
                        results["asn_details"] = {
                            "asn": asn_num,
                            "name": asn_data.get("name", ""),
                            "description": asn_data.get("description_short", ""),
                            "country": asn_data.get("country_code", ""),
                            "website": asn_data.get("website", ""),
                            "email_contacts": asn_data.get("email_contacts", [])[:3],
                            "abuse_contacts": asn_data.get("abuse_contacts", [])[:3],
                        }
        except Exception:
            pass

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


# -- 4. Shodan (free tier - no key for basic) ---------------------
async def shodan_lookup(target: str, **kw) -> dict:
    """Shodan internet intelligence lookup."""
    ip = target
    if not _is_ip(target):
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, target)
        except socket.gaierror:
            return {"target": target, "error": "Could not resolve"}

    import os
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

    # Paid API with key
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), connector=get_aiohttp_connector()) as session:
            async with session.get(f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "target": target,
                        "ip": ip,
                        "source": "shodan_api",
                        "ports": data.get("ports", []),
                        "vulns": data.get("vulns", []),
                        "os": data.get("os"),
                        "org": data.get("org", ""),
                        "isp": data.get("isp", ""),
                        "hostnames": data.get("hostnames", []),
                        "services": [
                            {"port": s.get("port"), "transport": s.get("transport"), "product": s.get("product", ""), "version": s.get("version", "")}
                            for s in data.get("data", [])[:20]
                        ],
                    }
    except Exception as e:
        return {"target": target, "ip": ip, "error": str(e)[:80]}

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
