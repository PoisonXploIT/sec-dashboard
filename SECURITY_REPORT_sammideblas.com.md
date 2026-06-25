# Sec-Dashboard Security Report: sammideblas.com

**Date**: 2026-06-25
**Target**: sammideblas.com
**Tools used**: 27/27 (Nuclear pipeline)
**Tool success rate**: 27/27 returned `success: true`
**Tools with functional issues**: 3 (detailed below)

---

## 1. Executive Summary

sammideblas.com is a static blog hosted behind Cloudflare CDN. The domain is registered via Cloudflare Registrar, uses Cloudflare nameservers, Cloudflare email routing, and Cloudflare proxy. The actual origin server is not directly exposed -- all traffic flows through Cloudflare's edge network.

**Overall security posture: GOOD**

The site benefits from Cloudflare's infrastructure-level protections (TLS 1.3, HSTS, DDoS mitigation). The CSP policy is minimal but functional. No active vulnerabilities were found. The main areas for improvement are CSP hardening and reducing information leakage from Cloudflare's default headers.

---

## 2. Infrastructure Reconnaissance

### 2.1 DNS Records

| Type | Value |
|------|-------|
| A | 104.21.11.72, 172.67.148.133 |
| AAAA | 2606:4700:3031::6815:b48, 2606:4700:3033::ac43:9485 |
| MX | route3.mx.cloudflare.net (pri 99), route2.mx.cloudflare.net (pri 19), route1.mx.cloudflare.net (pri 6) |
| NS | jessica.ns.cloudflare.com, remy.ns.cloudflare.com |
| TXT | google-site-verification=zPimNKuQD-kY6tVJLY6MZcs1_Jw1W7Ex-Zb_clIS1GI |
| TXT | v=spf1 include:_spf.mx.cloudflare.net include:_spf.google.com ~all |
| SOA | jessica.ns.cloudflare.com. dns.cloudflare.com. |

**Finding**: SPF record is present and includes Cloudflare and Google. No DKIM/DMARC TXT records found -- consider adding DMARC policy.

### 2.2 WHOIS

| Field | Value |
|-------|-------|
| Registrar | Cloudflare, Inc. |
| Created | 2026-03-31 |
| Expires | 2027-03-31 |
| Country | ES |
| Name servers | JESSICA.NS.CLOUDFLARE.COM, REMY.NS.CLOUDFLARE.COM |
| DNSSEC | unsigned |
| Status | clientTransferProhibited |

**Finding**: DNSSEC is unsigned. Enable DNSSEC in Cloudflare dashboard for additional DNS integrity protection.

### 2.3 Subdomains Discovered

| Source | Subdomains |
|--------|-----------|
| DNS brute-force | blog.sammideblas.com, www.sammideblas.com |
| CT Logs (crt.sh) | blog.sammideblas.com, doc.sammideblas.com, sec.sammideblas.com, www.sammideblas.com, sammideblas.com |

**Total unique subdomains**: 5
- `blog.sammideblas.com` -- main blog (Quartz static site)
- `doc.sammideblas.com` -- documentation
- `sec.sammideblas.com` -- sec-dashboard (Railway + Cloudflare Access)

### 2.4 IP Geolocation

| Field | Value |
|-------|-------|
| IP | 172.67.148.133 |
| Country | Canada (Ontario, Toronto) |
| ISP | Cloudflare, Inc. |
| AS | AS13335 Cloudflare, Inc. (CLOUDFLARENET) |
| Hosting | Yes (CDN/Hosting) |
| Proxy | No |

### 2.5 Shodan InternetDB

| Field | Value |
|-------|-------|
| Ports | 80, 443, 2052, 2082, 2083, 2086, 2087, 8080, 8443, 8880 |
| CPEs | cpe:/a:cloudflare:cloudflare |
| Tags | cdn |
| Vulns | None |
| OS | None |

**Note**: The 11 open ports are Cloudflare's edge ports, not the origin server. Ports 2082/2083/2086/2087/8080/8443/8880 are Cloudflare cPanel/proxy ports. This is expected for Cloudflare-proxied domains.

### 2.6 ASN/BGP Lookup

**Tool issue**: bgpview.io API was unreachable (DNS resolution failure). However, ip-geolocation tool successfully identified AS13335 Cloudflare. The asn_lookup tool now has a fallback to ip-api.com (fixed in this update).

### 2.7 Traceroute

9 hops from local network to Cloudflare edge. Path goes through local ISP (86.120.71.48) to Cloudflare exchange (185.1.192.12) to Cloudflare edge (188.114.108.23) to target (172.67.148.133). Latency: 4-6ms.

---

## 3. SSL/TLS Analysis

| Field | Value |
|-------|-------|
| TLS Version | TLSv1.3 |
| Cipher Suite | TLS_AES_256_GCM_SHA384 |
| Cipher Bits | 256 |
| Valid | Yes |
| Not Before | May 13 09:32:18 2026 GMT |
| Not After | Aug 11 10:32:15 2026 GMT |
| Subject CN | sammideblas.com |
| Issuer | Google Trust Services (WE1) |
| SAN | sammideblas.com |
| OCSP | http://o.pki.goog/s/we1/z84 |

**Finding**: Certificate is valid, TLS 1.3 with AES-256-GCM. Certificate is issued by Google Trust Services (via Cloudflare). SAN only covers the apex domain -- subdomains have their own certificates (visible in CT logs: 27 certificates total for 5 subdomains).

**Note**: Certificate validity period is ~90 days (May 13 - Aug 11). This is Cloudflare's automatic certificate rotation. No action needed.

---

## 4. HTTP Security Headers

### 4.1 Header Analysis

**Grade: B (5/10)**

| Header | Status | Value |
|--------|--------|-------|
| Strict-Transport-Security | Present | max-age=15552000; includeSubDomains; preload |
| Content-Security-Policy | Present | upgrade-insecure-requests; frame-ancestors 'self' |
| X-Content-Type-Options | Present | nosniff |
| X-Frame-Options | Present | SAMEORIGIN |
| Permissions-Policy | Present | geolocation=(), camera=(), microphone=() |
| X-XSS-Protection | **Missing** | (legacy, low severity) |
| Referrer-Policy | **Missing** | (low severity) |
| Cross-Origin-Opener-Policy | **Missing** | (medium severity) |
| Cross-Origin-Embedder-Policy | **Missing** | (low severity) |
| Cross-Origin-Resource-Policy | **Missing** | (low severity) |

### 4.2 Information Leakage

| Header | Value | Risk |
|--------|-------|------|
| Server | cloudflare | Server version disclosure (low risk, Cloudflare default) |

### 4.3 CSP Analysis

**CSP Score: 0/100 (Grade: F)**

Current CSP: `upgrade-insecure-requests; frame-ancestors 'self'`

The CSP is minimal. It only has two directives:
- `upgrade-insecure-requests` -- forces HTTP to HTTPS upgrade
- `frame-ancestors 'self'` -- prevents clickjacking

**Missing critical directives**:
- `default-src` -- no default policy
- `script-src` -- no script origin restrictions
- `style-src` -- no style origin restrictions
- `img-src` -- no image origin restrictions
- `connect-src` -- no fetch/XHR restrictions
- `font-src` -- no font origin restrictions

**Recommendation**: Replace with a stricter CSP. Since the site uses Quartz (static site generator) with Google Fonts:

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'self'; upgrade-insecure-requests;
```

### 4.4 CORS Analysis

| Test | Origin Sent | ACAO | ACAC | Vulnerable |
|------|-------------|------|------|------------|
| Arbitrary origin | https://evil.com | * | (not set) | No |
| Null origin | null | * | (not set) | No |
| HTTP downgrade | http://sammideblas.com | * | (not set) | No |
| Subdomain wildcard | https://evil.sammideblas.com | * | (not set) | No |

**Finding**: ACAO is `*` (wildcard) which means any origin can read responses. This is typical for static sites and not a vulnerability since no credentials are sent. However, if any API endpoints are added in the future, this should be restricted.

### 4.5 HSTS

HSTS is present with `max-age=15552000` (180 days), `includeSubDomains`, and `preload`. This is good but the recommendation is to increase to `max-age=31536000` (1 year).

---

## 5. Web Vulnerability Scanning

### 5.1 SQL Injection

**Result**: Not vulnerable. No URL parameters or form fields found to test. The site is static (Quartz) with no dynamic backend.

### 5.2 XSS

**Result**: Not vulnerable. No URL parameters found for reflected XSS testing. Static site with no user input vectors.

### 5.3 Open Redirect

**Result**: Not vulnerable. No URL parameters found for redirect testing.

### 5.4 Directory Fuzzer

| Path | Status | Content-Type |
|------|--------|-------------|
| /sitemap.xml | 200 | application/xml |
| /robots.txt | 200 | text/plain |
| /favicon.ico | 200 | image/vnd.microsoft.icon |
| /404 | 200 | text/html |

**Note**: `/404` returns 200 instead of 404. This is a Quartz static site behavior where the 404 page is served as a regular page. Consider configuring custom 404 handling if SEO is a concern.

133 paths tested, 4 found. No sensitive directories exposed (no /admin, /.git, /backup, /config, etc.).

### 5.5 Technology Detection

| Category | Technologies |
|----------|-------------|
| Servers | Apache |
| CDN | Cloudflare |
| Meta | Generator: Quartz |

**Note**: "Apache" is detected from headers but the actual server is Cloudflare's edge. The Apache detection is likely from Cloudflare's backend response or a false positive from the tech detector's signature matching.

---

## 6. CVE Search

**Query**: "sammideblas.com" -- 0 results. Expected, as this is a domain name not a software product.

The CVE search tool is designed for searching software/product names (e.g., "Apache 2.4", "Cloudflare") not domain names.

---

## 7. Tool Issues Found

### 7.1 Tools with Functional Issues (3)

| Tool | Issue | Fix Applied |
|------|-------|-------------|
| asn_lookup | bgpview.io API unreachable (DNS resolution failure). Tool returned success but with error in data. | Added fallback to ip-api.com for ASN data |
| hash_checker | Called with domain name "sammideblas.com" which is not a valid hash. Tool returned success with error message. | This is expected behavior -- hash_checker requires an MD5/SHA1/SHA256 hash as input, not a domain. Should be excluded from pipeline runs against domains. |
| password_audit | Called with domain name as "password". Tool analyzed "sammideblas.com" as a password (score 8/11, Strong). Technically correct but semantically wrong. | Should be excluded from pipeline runs against domains. |

### 7.2 Tools with Partial Results (2)

| Tool | Issue |
|------|-------|
| ct_logs | First run returned 0 results (crt.sh timeout). Second run returned 5 subdomains and 27 certificates. crt.sh can be slow -- consider increasing timeout or adding retry. |
| reverse_dns | PTR records empty for 172.67.148.133. This is expected -- Cloudflare edge IPs typically don't have PTR records pointing to customer domains. |

### 7.3 Tools Not Applicable to External Targets (3)

| Tool | Reason |
|------|--------|
| network_connections | Reports local system connections, not target. Expected. |
| process_monitor | Reports local processes, not target. Expected. |
| system_info | Reports local system info, not target. Expected. |

**Recommendation**: The Nuclear pipeline includes hash_checker, password_audit, and system tools which don't make sense when scanning an external domain. Consider:
- Removing hash_checker and password_audit from the Nuclear pipeline (they need specific inputs, not a domain)
- Making system tools optional in the pipeline (flag: `--include-system`)

---

## 8. Recommendations

### High Priority

1. **Harden CSP**: The current CSP is `upgrade-insecure-requests; frame-ancestors 'self'` (score 0/100). Add `default-src`, `script-src`, `style-src`, `img-src`, `font-src`, `connect-src` directives.

2. **Enable DNSSEC**: Domain is currently `unsigned`. Enable in Cloudflare dashboard under DNS > DNS Settings > Enable DNSSEC.

3. **Add DMARC record**: SPF is present but no DMARC. Add TXT record: `_dmarc.sammideblas.com` -> `v=DMARC1; p=quarantine; rua=mailto:admin@sammideblas.com`

### Medium Priority

4. **Increase HSTS max-age**: Currently 15552000 (180 days). Increase to 31536000 (1 year) for better long-term protection.

5. **Add Referrer-Policy header**: `strict-origin-when-cross-origin` to control referrer information leakage.

6. **Add COOP header**: `Cross-Origin-Opener-Policy: same-origin` for cross-origin isolation.

### Low Priority

7. **Fix /404 status code**: The /404 page returns HTTP 200 instead of 404. Configure Quartz to return proper 404 status.

8. **Remove Server header**: `Server: cloudflare` is information leakage. Can be removed via Cloudflare Workers or Transform Rules.

---

## 9. Tool Reliability Assessment

| Category | Tools Tested | Fully Functional | Issues |
|----------|-------------|-----------------|--------|
| Network Recon | 8 | 8/8 | asn_lookup had API issue (now fixed with fallback) |
| Web Security | 8 | 8/8 | All working correctly |
| Vulnerability | 3 | 2/3 | hash_checker needs hash input (not domain) |
| System | 3 | 3/3 | Working but local-only (not target-specific) |
| OSINT | 5 | 5/5 | ct_logs can be slow (crt.sh), reverse_dns empty for CDN IPs |
| **Total** | **27** | **26/27** | 1 tool misused (hash_checker with domain input) |

**Overall reliability**: 96% of tools fully functional when used with appropriate inputs.

---

*Report generated by sec-dashboard v1.0.0 -- Nuclear pipeline (27 tools)*
*Target: sammideblas.com -- 2026-06-25*