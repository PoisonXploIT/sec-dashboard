"""Network Recon tools — pure Python, no external binaries required."""
import asyncio
import socket
import ssl
import struct
import time
import json
from typing import Any

import aiohttp


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
    param = "-n" if True else "-c"  # Windows
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
    cmd = ["tracert", "-d", "-h", str(max_hops), host]

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
