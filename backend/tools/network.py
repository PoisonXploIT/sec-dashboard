"""Network Recon tools — pure Python, no external binaries required."""
import asyncio
import re
import socket
import ssl
import struct
import time
import json
from typing import Any
from urllib.parse import urlparse

import aiohttp

from backend.tools.osint import _is_ip, ct_logs


# ── 1. Port Scanner ────────────────────────────────────────────
async def port_scanner(host: str, ports: str = "top100", timeout: float = 1.0, **kw) -> dict:
    """Fast async TCP port scanner with service detection."""
    common_ports = {
        "top20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
        "top100": [20, 21, 22, 23, 25, 53, 80, 81, 110, 111, 119, 135, 139, 143, 161, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 3128, 3306, 3389, 4443, 5432, 5900, 5901, 6379, 6667, 7001, 7443, 8000, 8001, 8008, 8009, 8080, 8081, 8083, 8443, 8880, 8888, 9000, 9090, 9200, 9443, 10000, 11211, 27017, 27018, 28017, 50000, 50070],
        "all": list(range(1, 1025)),
    }
    port_list = common_ports.get(ports, common_ports["top100"])
    if ports.isdigit():
        port_list = [int(ports)]
    elif "," in ports or "-" in ports:
        # Parse custom port spec: "80,443,8080" or "1-1024" or mix
        port_list = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    lo, hi = part.split("-", 1)
                    port_list.extend(range(int(lo), int(hi) + 1))
                except ValueError:
                    pass
            elif part.isdigit():
                port_list.append(int(part))

    open_ports = []
    service_map = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
        161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
        514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
        1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
        3000: "Dev", 3128: "Proxy", 3306: "MySQL", 3389: "RDP", 4443: "HTTPS-alt",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 6667: "IRC", 7001: "WebLogic",
        7443: "HTTPS-alt", 8000: "HTTP-alt", 8001: "HTTP-alt", 8008: "HTTP-alt",
        8080: "HTTP-Proxy", 8081: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt",
        9000: "HTTP-alt", 9090: "HTTP-alt", 9200: "Elasticsearch", 10000: "Webmin",
        11211: "Memcached", 27017: "MongoDB", 50000: "SAP",
    }

    # Detect if host is IPv6
    is_ipv6 = ":" in host
    sem = asyncio.Semaphore(200)

    async def check_port(port: int):
        async with sem:
            # Try IPv4 first, then IPv6 if host resolves to it
            families = []
            try:
                infos = await asyncio.get_event_loop().getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
                families = list(set(i[0] for i in infos))
            except socket.gaierror:
                families = [socket.AF_INET6 if is_ipv6 else socket.AF_INET]

            for family in families:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, family=family), timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    service = service_map.get(port, "unknown")
                    ip_ver = "IPv6" if family == socket.AF_INET6 else "IPv4"
                    open_ports.append({"port": port, "state": "open", "service": service, "ip_version": ip_ver})
                    return  # Port open, no need to try other family
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass

    start = time.time()
    await asyncio.gather(*[check_port(p) for p in port_list])
    elapsed = round(time.time() - start, 2)
    open_ports.sort(key=lambda x: x["port"])

    return {
        "host": host,
        "scanned_ports": len(port_list),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "elapsed_seconds": elapsed,
    }


# ── 2. DNS Recon ───────────────────────────────────────────────
async def dns_recon(domain: str, **kw) -> dict:
    """DNS record enumeration."""
    import dns.resolver
    import dns.exception

    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]

    for rtype in record_types:
        try:
            answers = await asyncio.to_thread(
                dns.resolver.resolve, domain, rtype, lifetime=5
            )
            entries = []
            for rdata in answers:
                entries.append(str(rdata))
            if entries:
                records[rtype] = entries
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass

    # Try reverse DNS on A records
    reverse_dns = []
    if "A" in records:
        for ip in records["A"][:3]:
            try:
                hostname = await asyncio.to_thread(socket.gethostbyaddr, ip)
                reverse_dns.append({"ip": ip, "hostname": hostname[0]})
            except socket.herror:
                pass

    return {
        "domain": domain,
        "records": records,
        "reverse_dns": reverse_dns,
        "record_count": sum(len(v) for v in records.values()),
    }


# ── 3. Subdomain Enum ─────────────────────────────────────────
async def subdomain_enum(domain: str, wordlist: str = "quick", **kw) -> dict:
    """Subdomain discovery via DNS resolution."""
    subdomains_wordlist = {
        "quick": ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
                  "ns3", "dns", "dns1", "dns2", "proxy", "vpn", "admin", "panel", "portal",
                  "dev", "staging", "test", "api", "app", "beta", "demo", "blog", "shop",
                  "cdn", "media", "static", "img", "images", "assets", "files", "download",
                  "upload", "cloud", "s3", "aws", "git", "gitlab", "ci", "jenkins", "jira",
                  "confluence", "wiki", "docs", "help", "support", "status", "monitor",
                  "grafana", "prometheus", "kibana", "elastic", "db", "database", "mysql",
                  "postgres", "redis", "mongo", "mssql", "ftp", "sftp", "backup", "bak",
                  "old", "new", "web", "intranet", "internal", "hr", "crm", "erp", "mx",
                  "autodiscover", "remote", "gateway", "firewall", "exchange", "owa"],
        "full": None,  # Would load from file
    }

    words = subdomains_wordlist.get(wordlist, subdomains_wordlist["quick"])
    if not words:
        words = subdomains_wordlist["quick"]

    found = []
    sem = asyncio.Semaphore(100)

    async def check_subdomain(sub: str):
        async with sem:
            fqdn = f"{sub}.{domain}"
            try:
                result = await asyncio.to_thread(socket.gethostbyname, fqdn)
                found.append({"subdomain": fqdn, "ip": result})
            except socket.gaierror:
                pass

    start = time.time()
    await asyncio.gather(*[check_subdomain(w) for w in words])
    elapsed = round(time.time() - start, 2)
    found.sort(key=lambda x: x["subdomain"])

    return {
        "domain": domain,
        "subdomains_found": found,
        "count": len(found),
        "wordlist_size": len(words),
        "elapsed_seconds": elapsed,
    }


# ── Subdomain Takeover ───────────────────────────────────
_TAKEOVER_MAX_SUBS = 50


def _match_platform(cname: str) -> str | None:
    """Map a CNAME target to the platform that would serve it."""
    c = (cname or "").lower().rstrip(".")
    if c.endswith((".github.io", ".githubpages.dev")):
        return "github_pages"
    if c.endswith((".herokuapp.com", ".onheroku.com")):
        return "heroku"
    if re.search(r"\.s3[a-z0-9.-]*\.amazonaws\.com$", c) or c.endswith(".website.amazonaws.com"):
        return "s3"
    return None


async def _takeover_dns(host: str) -> dict:
    """CNAME + A resolution for one candidate (dnspython in a thread)."""
    import dns.resolver
    import dns.exception

    info = {"cname": None, "a_resolved": False, "nxdomain": False}
    try:
        answers = await asyncio.to_thread(
            dns.resolver.resolve, host, "CNAME", lifetime=4
        )
        info["cname"] = str(answers[0]).rstrip(".")
    except dns.resolver.NXDOMAIN:
        info["nxdomain"] = True
        return info
    except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
        pass
    except Exception:
        pass
    try:
        await asyncio.to_thread(dns.resolver.resolve, host, "A", lifetime=4)
        info["a_resolved"] = True
    except dns.resolver.NXDOMAIN:
        info["nxdomain"] = True
    except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
        pass
    except Exception:
        pass
    return info


async def _takeover_probe(sub: str) -> int | None:
    """HTTPS status of the candidate; None when unreachable."""
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            async with session.get(f"https://{sub}", allow_redirects=True) as resp:
                return resp.status
    except Exception:
        return None


async def subdomain_takeover(domain: str, **kw) -> dict:
    """Dangling CNAME detection for GitHub Pages / Heroku / S3.

    Candidate subdomains come from CT logs (crt.sh). Each one is resolved
    for its CNAME; targets pointing at a claimable platform are probed and
    flagged when nothing live answers (no A record, unreachable or 404/503).
    External sources failing degrade the result instead of breaking the scan.
    """
    target = domain or ""
    if "://" in target:
        target = urlparse(target).netloc or target
    host = target.split("/")[0].split(":")[0].strip().lower()
    if not host or _is_ip(host):
        return {"domain": host, "error": "Takeover requires a domain, not an IP"}

    ct = await ct_logs(host)
    subs = [s for s in ct.get("subdomains", []) if s != host][:_TAKEOVER_MAX_SUBS]

    async def check(sub: str) -> dict | None:
        info = await _takeover_dns(sub)
        if info["nxdomain"] or not info["cname"]:
            return None
        platform = _match_platform(info["cname"])
        if not platform:
            return {
                "sub": sub,
                "cname": info["cname"],
                "platform": None,
                "dangling": False,
                "http_status": None,
            }
        status = await _takeover_probe(sub)
        dangling = (not info["a_resolved"]) or (status is None) or status in (404, 503)
        return {
            "sub": sub,
            "cname": info["cname"],
            "platform": platform,
            "dangling": dangling,
            "http_status": status,
        }

    results = await asyncio.gather(*(check(s) for s in subs))
    hits = [r for r in results if r is not None]
    takeovers = [h for h in hits if h["platform"] and h["dangling"]]

    out = {
        "domain": host,
        "checked": len(subs),
        "candidates_with_cname": len(hits),
        "takeovers": takeovers,
        "count": len(takeovers),
    }
    if ct.get("error"):
        out["ct_error"] = ct["error"]
    return out



# ── 4. HTTP Probe ──────────────────────────────────────────────
async def http_probe(url: str, **kw) -> dict:
    """HTTP/HTTPS probing with headers, tech detection, and response analysis."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    results = []
    for scheme_attempt in [url]:
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15),
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(scheme_attempt, allow_redirects=True) as resp:
                    body = await resp.text()
                    headers = dict(resp.headers)

                    # Detect technologies from headers and body
                    techs = []
                    server = headers.get("Server", "")
                    if server:
                        techs.append(f"Server: {server}")
                    powered_by = headers.get("X-Powered-By", "")
                    if powered_by:
                        techs.append(f"Runtime: {powered_by}")

                    body_lower = body.lower()
                    tech_signatures = {
                        "WordPress": ["wp-content", "wp-includes", "wordpress"],
                        "jQuery": ["jquery"],
                        "Bootstrap": ["bootstrap"],
                        "React": ["react", "_reactRoot"],
                        "Vue.js": ["vue.js", "__vue__", "v-cloak"],
                        "Angular": ["ng-version", "angular"],
                        "Laravel": ["laravel", "csrf-token"],
                        "Django": ["csrfmiddlewaretoken", "django"],
                        "Flask": ["werkzeug"],
                        "nginx": ["nginx"],
                        "Apache": ["apache"],
                        "IIS": ["microsoft-iis", "x-aspnet"],
                        "PHP": [".php"],
                        "ASP.NET": ["__viewstate", "asp.net"],
                        "Tomcat": ["tomcat", "catalina"],
                    }
                    for tech_name, sigs in tech_signatures.items():
                        for sig in sigs:
                            if sig in body_lower or sig in server.lower() or (powered_by and sig in powered_by.lower()):
                                if tech_name not in techs:
                                    techs.append(tech_name)
                                break

                    results.append({
                        "url": str(resp.url),
                        "status": resp.status,
                        "content_type": headers.get("Content-Type", ""),
                        "server": server,
                        "content_length": len(body),
                        "redirect_chain": str(resp.history) if resp.history else None,
                        "technologies": techs,
                        "headers": {k: v for k, v in headers.items()},
                    })
                    break
        except Exception as e:
            results.append({"url": scheme_attempt, "error": str(e)})
            # Try http if https failed
            if scheme_attempt.startswith("https://"):
                alt = scheme_attempt.replace("https://", "http://", 1)
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=15)
                    ) as session:
                        async with session.get(alt, allow_redirects=True) as resp:
                            results = [{
                                "url": str(resp.url),
                                "status": resp.status,
                                "server": resp.headers.get("Server", ""),
                                "technologies": [],
                                "headers": {k: v for k, v in resp.headers.items()},
                            }]
                except Exception as e2:
                    results.append({"url": alt, "error": str(e2)})

    return {"target": url, "probes": results}


# ── 5. Whois Lookup ────────────────────────────────────────────
async def whois_lookup(domain: str, **kw) -> dict:
    """Domain WHOIS information."""
    try:
        import whois as python_whois
        w = await asyncio.to_thread(python_whois.whois, domain)
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": w.name_servers if w.name_servers else [],
            "org": w.org,
            "country": w.country,
            "emails": w.emails if w.emails else [],
            "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            "dnssec": w.dnssec,
        }
    except ImportError:
        # Fallback: use socket-based whois
        return await _raw_whois(domain)
    except Exception as e:
        return {"domain": domain, "error": str(e)}


async def _raw_whois(domain: str) -> dict:
    """Raw socket-based WHOIS fallback."""
    try:
        # Determine whois server
        tld = domain.split(".")[-1].lower()
        servers = {"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
                   "org": "whois.pir.org", "io": "whois.nic.io", "es": "whois.nic.es",
                   "uk": "whois.nic.uk", "de": "whois.denic.de", "fr": "whois.nic.fr"}
        whois_server = servers.get(tld, f"whois.nic.{tld}")

        def do_whois():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((whois_server, 43))
            s.send(f"{domain}\r\n".encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            return response.decode("utf-8", errors="ignore")

        data = await asyncio.to_thread(do_whois)
        return {"domain": domain, "raw": data[:3000], "whois_server": whois_server}
    except Exception as e:
        return {"domain": domain, "error": str(e)}


# ── 6. Ping Sweep ──────────────────────────────────────────────
async def ping_sweep(host: str, count: int = 4, **kw) -> dict:
    """ICMP ping reachability check."""
    import platform
    param = "-n" if platform.system() == "Windows" else "-c"  # L1
    cmd = ["ping", param, str(count), host]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="ignore")

        # Parse results
        alive = "TTL=" in output or "ttl=" in output
        stats = {}
        for line in output.split("\n"):
            if "Average" in line or "average" in line:
                stats["summary"] = line.strip()
            if "Lost" in line or "lost" in line:
                stats["loss"] = line.strip()

        return {
            "host": host,
            "alive": alive,
            "count": count,
            "output": output.strip(),
            "stats": stats,
        }
    except Exception as e:
        return {"host": host, "alive": False, "error": str(e)}


# ── 7. Traceroute ──────────────────────────────────────────────
async def traceroute(host: str, max_hops: int = 15, **kw) -> dict:
    """Network path tracing."""
    import platform
    if platform.system() == "Windows":  # L1
        cmd = ["tracert", "-d", "-h", str(max_hops), host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), host]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode("utf-8", errors="ignore")

        hops = []
        for line in output.split("\n"):
            line = line.strip()
            if line and line[0].isdigit():
                parts = line.split()
                hop_num = parts[0] if parts else "?"
                # Extract IPs from the line
                ips = []
                times = []
                for p in parts[1:]:
                    if p.replace(".", "").replace(":", "").replace("[", "").replace("]", "").replace("*", ""):
                        if any(c.isdigit() for c in p):
                            if "ms" in p.lower():
                                times.append(p)
                            elif "." in p or ":" in p:
                                ips.append(p.strip("[]"))
                hops.append({
                    "hop": hop_num,
                    "ips": ips,
                    "times": times,
                    "raw": line,
                })

        return {
            "host": host,
            "hops": hops,
            "hop_count": len(hops),
            "raw_output": output.strip(),
        }
    except Exception as e:
        return {"host": host, "error": str(e)}


# ── 8. SSL/TLS Analyzer ────────────────────────────────────────
async def ssl_analyzer(host: str, port: int = 443, **kw) -> dict:
    """SSL/TLS certificate and cipher analysis."""
    def do_ssl():
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(10)
        conn.connect((host, port))
        cert = conn.getpeercert()
        cipher = conn.cipher()
        version = conn.version()
        conn.close()
        return cert, cipher, version

    try:
        cert, cipher, version = await asyncio.to_thread(do_ssl)

        # Parse cert
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        return {
            "host": host,
            "port": port,
            "tls_version": version,
            "cipher_suite": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "subject": subject,
            "issuer": issuer,
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [entry[1] for entry in cert.get("subjectAltName", ())],
            "ocsp": cert.get("OCSP", []),
            "valid": True,
        }
    except ssl.SSLCertVerificationError as e:
        return {"host": host, "port": port, "valid": False, "error": str(e)}
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}



# ── 9. SSL Deep Analyzer (F1-SSL) ─────────────────────────────
# stdlib-only (ssl/socket): TLS version probes, weak-cipher probes,
# HSTS header probe over raw TLS, OCSP stapling via a hand-built
# ClientHello with the status_request extension (RFC 6066), and a
# letter grade A+ to F computed from discrete checks.

_SSL_PROBE_TIMEOUT = 8.0
_HSTS_SHORT_MAX_AGE = 15552000  # 180 days, in seconds

_TLS_DISABLE_FLAG = {
    "1.0": "OP_NO_TLSv1",
    "1.1": "OP_NO_TLSv1_1",
    "1.2": "OP_NO_TLSv1_2",
    "1.3": "OP_NO_TLSv1_3",
}

_WEAK_CIPHER_STRINGS = ("RC4", "DES-CBC", "3DES", "NULL")

_OCSP_PROBE_CIPHERS = (
    0x1305, 0x1304, 0x1303, 0x1302, 0x1301,          # TLS 1.3 suites
    0xC030, 0xC031, 0xC02B, 0xC02F,                  # ECDHE RSA/ECDSA GCM
    0x009C, 0x009D, 0x009E,                         # AES-GCM (no PFS)
)


def _version_only_context(version: str) -> ssl.SSLContext:
    """Client context restricted to a single TLS version.

    Best effort: the restriction is expressed via OP_NO_* flags; if the
    local OpenSSL build cannot actually negotiate that version, the
    handshake fails and the probe reports "unsupported".
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for v, flag in _TLS_DISABLE_FLAG.items():
        if v != version and hasattr(ssl, flag):
            ctx.options |= getattr(ssl, flag)
    return ctx


def _tls_handshake(host: str, port: int, ctx: ssl.SSLContext,
                   timeout: float = _SSL_PROBE_TIMEOUT) -> tuple[str | None, str | None]:
    """Blocking handshake. Returns (version, cipher_name). Raises on failure."""
    sock = socket.socket()
    sock.settimeout(timeout)
    conn = ctx.wrap_socket(sock, server_hostname=host)
    conn.connect((host, port))
    try:
        return conn.version(), (conn.cipher() or (None, None))[0]
    finally:
        conn.close()


def _probe_tls_versions(host: str, port: int) -> dict:
    """Probe TLS 1.0/1.1/1.2/1.3 support and the default negotiation."""
    supported = {}
    for v in ("1.0", "1.1", "1.2", "1.3"):
        try:
            _tls_handshake(host, port, _version_only_context(v))
            supported[v] = True
        except Exception:
            supported[v] = False
    negotiated = None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        version, cipher = _tls_handshake(host, port, ctx)
        negotiated = {"version": version, "cipher": cipher}
    except Exception:
        pass
    return {"supported": supported, "negotiated": negotiated}


def _probe_weak_ciphers(host: str, port: int) -> list[str]:
    """Try to negotiate each weak family; only real successes are reported.

    If the local OpenSSL build refuses a cipher string (set_ciphers raises),
    that family is untestable and silently skipped: we never report a weak
    cipher we did not actually negotiate.
    """
    found = []
    for cs in _WEAK_CIPHER_STRINGS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers(cs)
        except (ssl.SSLError, ValueError):
            continue
        try:
            _version, cipher = _tls_handshake(host, port, ctx)
        except Exception:
            continue
        found.append(cipher or cs)
    return found


def _parse_hsts(value: str) -> dict:
    """Parse a Strict-Transport-Security header value."""
    out = {"max_age": None, "include_subdomains": False, "preload": False}
    for part in value.split(";"):
        part = part.strip()
        low = part.lower()
        if low.startswith("max-age="):
            try:
                out["max_age"] = int(part.split("=", 1)[1].strip().strip('"'))
            except (ValueError, IndexError):
                pass
        elif "includesubdomains" in low:
            out["include_subdomains"] = True
        elif "preload" in low:
            out["preload"] = True
    return out


def _probe_hsts(host: str, port: int) -> dict:
    """Send a minimal HTTP/1.0 GET over TLS and read the HSTS header."""
    def blocking() -> str | None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.socket()
        sock.settimeout(_SSL_PROBE_TIMEOUT)
        conn = ctx.wrap_socket(sock, server_hostname=host)
        conn.connect((host, port))
        try:
            req = (b"GET / HTTP/1.0\r\nHost: " + host.encode()
                   + b"\r\nConnection: close\r\nUser-Agent: sec-dashboard\r\n\r\n")
            conn.sendall(req)
            chunks: list[bytes] = []
            while True:
                try:
                    data = conn.recv(65536)
                except (socket.timeout, ssl.SSLException):
                    break
                if not data:
                    break
                chunks.append(data)
                if sum(map(len, chunks)) > 262144:
                    break
            raw = b"".join(chunks).decode("utf-8", "replace")
        finally:
            conn.close()
        head = raw.split("\r\n\r\n", 1)[0]
        for line in head.splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() == "strict-transport-security":
                    return v.strip()
        return None

    try:
        hsts_value = blocking()
    except Exception:
        hsts_value = None
    if hsts_value is None:
        return {"present": False, "max_age": None,
                "include_subdomains": False, "preload": False}
    parsed = _parse_hsts(hsts_value)
    parsed["present"] = True
    return parsed


# ── OCSP stapling: raw ClientHello with status_request ext ─────

def _build_ocsp_client_hello(host: str) -> bytes:
    """Build a minimal TLS 1.2/1.3 ClientHello offering the
    status_request (OCSP) extension plus SNI, ready to send on a socket."""
    import random as _random

    legacy_random = _random.randbytes(32)
    suites = b"".join(struct.pack(">H", c) for c in _OCSP_PROBE_CIPHERS)

    sni_inner = struct.pack(">H", len(host)) + b"\x00" \
        + struct.pack(">H", len(host)) + host.encode()
    ext_sni = struct.pack(">HH", 0, len(sni_inner)) + sni_inner
    ext_status = struct.pack(">HH", 5, 0)  # status_request, empty data

    extensions = ext_sni + ext_status
    body = (struct.pack(">H", 0x0303) + legacy_random + b"\x00"
            + struct.pack(">H", len(suites)) + suites
            + b"\x00"
            + struct.pack(">H", len(extensions)) + extensions)
    hello = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16" + struct.pack(">H", 0x0303) + struct.pack(">H", len(hello)) + hello


def _parse_stapling_from_records(data: bytes) -> bool | None:
    """Parse TLS records for a ServerHello; True if it carries the
    status_response extension (OCSP stapled), False if not, None if no
    conclusive ServerHello was found in `data` yet."""
    pos = 0
    while pos + 5 <= len(data):
        rtype = data[pos]
        rlen = struct.unpack(">H", data[pos + 5:pos + 7])[0]
        payload = data[pos + 5:pos + 5 + rlen]
        pos += 5 + rlen
        if rtype != 0x16 or not payload:
            continue
        mtype = payload[0]
        if mtype == 2:  # ServerHello
            body = payload[4:]
            if len(body) < 7:
                return None
            sid_len = body[34]
            pos_ciphers = 35 + sid_len
            if len(body) < pos_ciphers + 3:
                return None
            ciphers_len = struct.unpack(">H", body[pos_ciphers:pos_ciphers + 2])[0]
            off = pos_ciphers + 2 + ciphers_len
            comp_len = body[off]
            off += 1 + comp_len
            if len(body) < off + 2:
                return None
            exts_len = struct.unpack(">H", body[off:off + 2])[0]
            off += 2
            if off + exts_len > len(body):
                return None  # extensions block incomplete
            exts = body[off:off + exts_len]
            epos = 0
            while epos + 4 <= len(exts):
                etype = struct.unpack(">H", exts[epos:epos + 2])[0]
                elen = struct.unpack(">H", exts[epos + 2:epos + 4])[0]
                epos += 4 + elen
                if etype == 5:
                    return True
            return False
        if mtype in (4, 11, 15, 20):  # NewSessionTicket/Certificate/CertVerify/Finished
            continue
        return None  # alert or other: no conclusive answer
    return None


def _probe_ocsp_stapling(host: str, port: int) -> str:
    """Send the raw ClientHello and read the server's first flight.

    Returns "yes" (status_response seen), "no" (clean ServerHello without
    it) or "unknown" (timeout / alert / garbage)."""
    def blocking() -> str:
        sock = socket.socket()
        sock.settimeout(_SSL_PROBE_TIMEOUT)
        sock.connect((host, port))
        try:
            sock.sendall(_build_ocsp_client_hello(host))
            buf = b""
            while True:
                result = _parse_stapling_from_records(buf)
                if result is not None:
                    return "yes" if result else "no"
                try:
                    chunk = sock.recv(65536)
                except (socket.timeout, OSError):
                    return "unknown"
                if not chunk:
                    return "unknown"
                buf += chunk
                if len(buf) > 1 << 20:
                    return "unknown"
        finally:
            sock.close()

    try:
        return blocking()
    except Exception:
        return "unknown"


def _probe_certificate(host: str, port: int) -> dict | None:
    """Certificate facts from a verification-free handshake."""
    import datetime

    def blocking() -> dict:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.socket()
        sock.settimeout(_SSL_PROBE_TIMEOUT)
        conn = ctx.wrap_socket(sock, server_hostname=host)
        conn.connect((host, port))
        try:
            cert = conn.getpeercert()
        finally:
            conn.close()
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        days_left = None
        expired = False
        try:
            end = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y GMT")
            now = datetime.datetime.utcnow()
            days_left = (end - now).days
            expired = end <= now
        except (KeyError, ValueError):
            pass
        return {
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("commonName", ""),
            "san": [entry[1] for entry in cert.get("subjectAltName", ())],
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "days_left": days_left,
            "expired": expired,
            "self_signed": bool(subject) and subject == issuer,
            "ocsp_responder": (cert.get("OCSP") or [None])[0],
        }

    try:
        return blocking()
    except Exception:
        return None


def _compute_grade(checks: list[dict]) -> str | None:
    """Letter grade A+ to F from the discrete checks.

    Start at A+; each failing/warning check caps the grade. Returns None
    if there are no checks (nothing was probed).
    """
    if not checks:
        return None
    scale = ["A+", "A", "A-", "B+", "B", "C", "D", "E", "F"]
    caps = {
        ("tls_legacy", "fail"): "F",
        ("weak_cipher", "fail"): "F",
        ("cert_expired", "fail"): "D",
        ("self_signed", "fail"): "C",
        ("no_forward_secrecy", "fail"): "B+",
        ("hsts_missing", "fail"): "A",
        ("hsts_short", "fail"): "A-",
    }
    cap = None
    for chk in checks:
        grade = caps.get((chk.get("id"), chk.get("status")))
        if grade is None:
            continue
        if cap is None or scale.index(grade) > scale.index(cap):
            cap = grade
    return cap if cap is not None else "A+"


def _build_ssl_checks(versions: dict, weak: list[str], hsts: dict,
                      ocsp: dict, cert: dict | None) -> list[dict]:
    checks: list[dict] = []

    legacy = [v for v in ("1.0", "1.1") if versions.get(v)]
    checks.append({
        "id": "tls_legacy",
        "status": "fail" if legacy else "pass",
        "detail": f"Legacy protocol accepted: {', '.join(legacy)}" if legacy
                  else "No TLS 1.0/1.1",
    })
    checks.append({
        "id": "weak_cipher",
        "status": "fail" if weak else "pass",
        "detail": f"Weak cipher negotiated: {', '.join(weak)}" if weak
                  else "No RC4/DES/3DES/NULL negotiated",
    })

    negotiated_cipher = (versions.get("negotiated") or {}).get("cipher") or ""
    has_pfs = ("ECDHE" in negotiated_cipher) or ("DHE" in negotiated_cipher)
    checks.append({
        "id": "no_forward_secrecy",
        "status": "fail" if not has_pfs else "pass",
        "detail": f"No PFS cipher negotiated ({negotiated_cipher})"
                  if not has_pfs else f"PFS cipher: {negotiated_cipher}",
    })

    if cert is None:
        checks.append({"id": "self_signed", "status": "warn",
                       "detail": "No certificate could be read"})
        checks.append({"id": "cert_expired", "status": "warn",
                       "detail": "No certificate could be read"})
    else:
        checks.append({
            "id": "self_signed",
            "status": "fail" if cert.get("self_signed") else "pass",
            "detail": f"Self-signed ({cert.get('subject')})"
                      if cert.get("self_signed") else "CA-issued certificate",
        })
        checks.append({
            "id": "cert_expired",
            "status": "fail" if cert.get("expired") else "pass",
            "detail": f"Certificate expired ({cert.get('not_after')})"
                      if cert.get("expired") else
                      f"{cert.get('days_left')} days left",
        })
        checks.append({
            "id": "cert_expiring",
            "status": "warn" if (cert.get("days_left") is not None
                                 and 0 < cert["days_left"] < 30) else "pass",
            "detail": f"Expires in {cert.get('days_left')} days"
                      if (cert.get("days_left") is not None
                          and 0 < cert["days_left"] < 30) else "Not expiring soon",
        })

    checks.append({
        "id": "hsts_missing",
        "status": "fail" if not hsts.get("present") else "pass",
        "detail": "Strict-Transport-Security header absent"
                  if not hsts.get("present") else "HSTS present",
    })
    if hsts.get("present"):
        short = (hsts.get("max_age") is None) or (hsts["max_age"] < _HSTS_SHORT_MAX_AGE)
        checks.append({
            "id": "hsts_short",
            "status": "fail" if short else "pass",
            "detail": f"HSTS max-age {hsts.get('max_age')} (< 180 days)"
                      if short else f"HSTS max-age {hsts['max_age']}",
        })

    ocsp_ok = (ocsp.get("stapling") == "yes") or bool(ocsp.get("responder"))
    checks.append({
        "id": "ocsp_unavailable",
        "status": "warn" if not ocsp_ok else "pass",
        "detail": f"OCSP stapling={ocsp.get('stapling')}, responder={'yes' if ocsp.get('responder') else 'no'}",
    })
    return checks


def _ssl_deep_scan_blocking(host: str, port: int) -> dict:
    """All probes in one blocking pass (called from a worker thread)."""
    versions = _probe_tls_versions(host, port)
    weak = _probe_weak_ciphers(host, port)
    hsts = _probe_hsts(host, port)
    ocsp = {"stapling": _probe_ocsp_stapling(host, port)}
    cert = _probe_certificate(host, port)
    if cert is not None:
        ocsp["responder"] = cert.get("ocsp_responder")
    else:
        ocsp["responder"] = None

    checks = _build_ssl_checks(versions, weak, hsts, ocsp, cert)
    return {
        "target": host,
        "port": port,
        "tls_versions": versions.get("supported"),
        "negotiated": versions.get("negotiated"),
        "weak_ciphers": weak,
        "hsts": hsts,
        "ocsp": ocsp,
        "cert": cert,
        "checks": checks,
        "grade": _compute_grade(checks),
    }


async def ssl_deep_analyzer(target: str, **kw) -> dict:
    """Deep SSL/TLS audit: grade A+ to F from protocol, cipher, HSTS and
    OCSP evidence. stdlib-only (ssl/socket); no external binaries."""
    import re as _re

    t = target.strip()
    if t.lower().startswith(("http://", "https://")):
        t = _re.sub(r"^https?://", "", t)
    if "/" in t:
        t = t.split("/")[0]
    host, _, port_s = t.partition(":")
    host = host.strip().lower()
    try:
        port = int(port_s) if port_s else 443
    except ValueError:
        return {"target": target, "error": f"Invalid port in {target!r}"}
    if not host:
        return {"target": target, "error": "Empty target"}

    try:
        result = await asyncio.to_thread(_ssl_deep_scan_blocking, host, port)
    except Exception as e:  # M1: never leak a traceback to the client
        return {"target": host, "port": port, "error": str(e)}

    if not any(result["tls_versions"].values()) and result["negotiated"] is None \
            and result["cert"] is None:
        return {"target": host, "port": port,
                "error": "No TLS handshake succeeded (port closed or filtered)"}
    return result
