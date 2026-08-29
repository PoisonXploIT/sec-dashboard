# User Guide (plain language)

This guide explains sec-dashboard in plain words, without losing technical rigor. It is the expanded version of the in-app Guide page: everything you can do, what each of the 52 tools does, when it is useful to you, what you put in and what comes out.

If a word looks scary, the sentence right after it explains it in plain terms.

---

## 1. What this thing is

sec-dashboard is a single web page (one `index.html`) served by a FastAPI backend, with a SQLite database (`data/sec.db`). You open it in a browser and it gives you:

- **52 security tools** grouped in 7 categories (Network Recon, Web Security, Vulnerability, System, OSINT, Email Security, RF Hardware).
- **Pipelines**: chains of tools that run in order (Fast / Deep / Full Depth / Nuclear).
- **History**: every scan and pipeline you have ever run, with search, pagination and formatted results.
- **Exports**: JSON, CSV and PDF, per item or in bulk.
- **Webhooks**: notifications to Discord, Slack or any HTTP endpoint when a run finishes.
- **Splunk auto-indexing**: every finished run can be sent straight into Splunk.
- **Proxy / anonymity**: route OSINT and web tools through TOR or any SOCKS5 proxy.
- **RF Hardware**: offline analysis of HackRF `.cff` captures and 802.11 WiFi `.pcap` files you upload.

Everything runs on one machine (the "server"). The browser is just the remote control.

## 2. Local mode vs remote mode

The app detects two modes, and this changes what is allowed:

| | Local mode | Remote mode (`SEC_DASHBOARD_REMOTE=1`, or auto-detected when `PORT` is set, e.g. on Railway) |
|---|---|---|
| Targets | Anything, including `localhost`, private IPs | Public targets only; private/loopback/link-local/metadata addresses are blocked (SSRF protection) |
| System tools (`Net Connections`, `Process Monitor`, `System Info`) | Work: they inspect **your** machine | **HTTP 403**: they would inspect the *server*, not your PC, so they are disabled by design |
| WiFi hardware polling (`WiFi Marauder Scan`, `M5Stick Networks`) | Work: they poll a viewer running on **your** PC | **HTTP 403**, same reason |
| Rate limits | Same as remote | 30 req/min per IP and per API key on scan/pipeline/target creation; 600 req/min on reads; the reset endpoint is capped at 5 req/hour |

Other protections that are always on: security headers (CSP, HSTS, `X-Content-Type-Options: nosniff`), SSRF validation on proxy and Splunk URLs, event logging (failed auth attempts are logged with the key truncated, never in full; blocked SSRF targets are logged as WARNING).

**Why do System and WiFi tools give 403 in the cloud?** Because they report on the machine where the dashboard runs. On a public server that is the *server's* machine: you would get the cloud box's processes and ports, which is useless to you and leaks server information. Same for the WiFi pollers: the URL they ask for (e.g. `http://127.0.0.1:5000`) points at a Flask viewer that runs on **your** computer next to your M5Stick hardware. From a cloud server, `127.0.0.1` is the cloud box itself — not your desk. So those tools only make sense when the dashboard runs locally, and remote deployments refuse them with 403. That is intentional, not a bug.

## 3. The API key: why it exists and where it lives

On a public deployment every `/api/*` request must present the right `X-API-Key` header, or you get `401 Invalid or missing API key`. The key exists so strangers cannot spend your server's CPU scanning random targets.

- Where it is stored **in your browser**: `localStorage['sec_api_key']`, under the dashboard's own origin only. It never goes to this repo, to logs, or anywhere else. Clearing your browser data for that site makes the dashboard ask for it again — that is normal.
- What happens with a wrong or missing key: API calls return 401 and the dashboard asks you for the key again (the prompt near the top of the page). Re-enter it and everything works.
- Extra layer: behind Cloudflare Access, requests are already authenticated by SSO (`Cf-Access-Authenticated-User-Email`), so the API key check is satisfied by your login.

## 4. Quick start

1. **Add a target.** Go to *Targets* → *Add Target*. Give it a name and a domain or IP (e.g. `example.com`). Your selected target persists across page reloads.
2. **Run a tool.** Go to *Tools*, click any tool card, pick your target from the popup. Results appear below the tools grid.
3. **Run a pipeline.** Go to *Pipeline*, pick a mode (Fast / Deep / Full Depth / Nuclear), select a target, *Start Pipeline*. Progress updates in real time with per-tool status.
4. **View results.** Go to *History*. Two tabs: *Scans* and *Pipelines*. Search filters by tool, target or status as you type. Click *View* for formatted results (pipelines show each tool's output individually, not raw JSON).
5. **Cancel a run.** Running items in History or on the Pipeline page show a *Cancel* button. Cancelled runs keep their record for audit but stop consuming CPU.
6. **Export.** Every scan and pipeline has *JSON* and *PDF* buttons. *Export All (JSON)* in History does a bulk export (Splunk/SIEM compatible). A CSV export (one row per finding) is also available per item.
7. **Webhooks.** *Webhooks* in the sidebar: add Discord, Slack or generic HTTP URLs and get notified when runs complete. *Test* sends a verification ping.
8. **Splunk.** *Splunk* in the sidebar: enter REST API URL (default `https://127.0.0.1:8089`), user, password, index. *Test Connection*, then enable auto-indexing. Every completed run is sent to Splunk automatically.
9. **Delete.** Each row has a *Del* button with confirmation. Scans, pipelines, targets and webhooks can all be deleted individually.
10. **Hardware & audit tools.** The *System* category includes tools that need no target domain/IP: `PS Security Audit`, `WiFi Marauder Scan`, `M5Stick Networks`. See section 8.
11. **RF capture analysis (upload).** The *RF Hardware* category analyzes captures offline, no target needed. See section 7.

## 5. Targets

A **target** is just a saved name + domain/IP pair so you do not retype it. Tools that take a "domain or IP" read it from the selected target; tools that take a URL let you type the full URL in the popup. Some tools are **special**: they ignore the target entirely and ask for their own input (a hash, a password, a CVE keyword) or no input at all (system tools, RF uploads).

In remote mode, targets are validated before saving: anything that resolves to a private, loopback or link-local address — or is a cloud metadata endpoint like `169.254.169.254` — is rejected with a clear reason and the attempt is logged.

## 6. The 52 tools, by category

For each tool: what it does, when you need it, what you put in, what comes out.

### 6.1 Network Recon (10)

| Tool | What it does | When you need it | Input | Output |
|---|---|---|---|---|
| Port Scanner | Fast TCP port scan with service detection | First look at what a host exposes: web, SSH, database ports | Domain or IP | Table of open ports with guessed services |
| DNS Recon | Enumerates DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) | Baseline of where a domain points and who runs mail/DNS | Domain | Records grouped by type, plus reverse DNS |
| Subdomain Enum | Finds subdomains by brute-forcing ~81 common names against DNS | Find staging, dev, forgotten hosts before they find you | Domain | List of live subdomains with IPs |
| HTTP Probe | Probes HTTP/HTTPS and detects the tech behind it | Quick "what is this site running" check | Domain or URL | Status code, server banner, tech stack, key headers |
| Whois Lookup | Pulls domain registration data | Know who registered a domain, since when, which registrars/NS | Domain | Registrar, creation/expiry dates, nameservers, country |
| Ping Sweep | ICMP reachability check | Cheap first filter: is the host even up? | Domain or IP | Alive status and latency stats |
| Traceroute | Traces the network path to the target | Debug "where does it get slow/blocked" between you and the target | Domain or IP | Hop list with IPs and per-hop times |
| SSL/TLS Analyzer | Inspects the certificate and cipher of a TLS endpoint | Check cert validity, SANs, protocol version before trusting/flagging it | Domain or IP | TLS version, cipher suite, cert validity dates, SAN list |
| SSL Deep Analyzer | Full TLS grading: legacy protocols, weak ciphers, HSTS, OCSP stapling | When you need a letter grade (A+ to F) and the reasons behind it | Domain or IP | Grade + checklist of what drags the score down |
| CAA Checker | Reads CAA records: which CAs are allowed to issue certs for this domain | Understand cert-issuance policy before a mis-issuance becomes an incident | Domain | CAA records, issue/wildcard policies |

### 6.2 Web Security (12)

| Tool | What it does | When you need it | Input | Output |
|---|---|---|---|---|
| Header Analyzer | Audits HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) | Fast "how hardened is this site" check for reports | URL | Letter grade (A+ to F) plus present/missing header list |
| Directory Fuzzer | Brute-forces ~133 common web paths (`/.git`, `/admin`, backups...) | Find pages the owner forgot to protect | URL | Found paths with their HTTP status codes |
| SQLi Scanner | Error-based and boolean-based SQL injection tests | Check whether query parameters leak into SQL | URL with parameters | Vulnerabilities with the payload that triggered them and evidence |
| XSS Scanner | Tests URL parameters for reflected cross-site scripting | Classic "does my input come back unsanitized" check | URL with parameters | Reflected payloads per parameter |
| CORS Checker | Runs 4 CORS misconfiguration tests | Find origins that can read your API cross-origin | URL | Origin reflection, wildcard findings, credentials flag |
| Tech Detector | Fingerprints the web stack: CMS, framework, CDN, analytics | Know what to expect before deeper testing | URL | Categorized technology list |
| CSP Analyzer | Scores Content Security Policy strength | When you need to say "CSP is weak, here is why" | URL | Score 0-100, grade, issue list, raw policy text |
| Open Redirect | Tests URL parameters for open redirects | Catch `?redirect=` tricks used in phishing chains | URL with parameters | Redirect chains that end at attacker-controlled hosts |
| Secret Leak Scan | Checks `.git/` access, API keys/tokens in known JS paths and robots.txt | The "oops, we committed the secret" check | URL | Exposed items with location and evidence |
| Favicon Fingerprint | MD5/SHA256 of `/favicon.ico` and common icon paths, matched against a local stack hash DB | Low-noise fingerprinting that survives CDN/proxy banners | URL | Matched stack from the icon hash |
| HTTP Methods | Checks which HTTP methods are allowed (PUT, DELETE, TRACE...) | Find write/trace verbs on endpoints that should be read-only | URL | Allowed methods with their response codes |
| Robots.txt Analyzer | Parses robots.txt for sensitive paths and misconfigurations | Free map of what the site *tells* crawlers not to touch | URL | Disallowed paths, sitemaps, notable misconfigs |

### 6.3 Vulnerability (7)

| Tool | What it does | When you need it | Input | Output |
|---|---|---|---|---|
| CVE Search | Searches NIST NVD by keyword or CVE ID | Look up a product you just fingerprinted | Keyword or `CVE-YYYY-NNNN` | CVEs with CVSS scores and severity |
| CVE Correlation | Cross-checks the detected stack against NVD + CISA KEV | Turn "what is running" into "which of it is known-broken" | Domain/IP (uses Tech Detector result) | Stack items matched to open CVEs / Known Exploited Vulnerabilities |
| Subdomain Takeover | Detects dangling CNAMEs via certificate-transparency logs | Catch subdomains pointing at dead cloud resources you could own | Domain | Dangling CNAME candidates with the provider (GitHub Pages, Heroku, S3...) |
| Hash Lookup | File-hash reputation via VirusTotal / MalwareBazaar | A file hash came up in an analysis; is it known-bad? | MD5 / SHA-1 / SHA-256 | Detection results from both databases |
| Password Audit | Strength analysis + breach-database check | Evaluate a password policy or a specific credential | Password (entered as the "target") | Score 0-11, entropy, how often it appears in breaches |
| ExploitDB Search | Public exploits for a product/version or CVE (exploit-db.com) | Before patching: is there public exploit code? | Product / version or CVE ID | Matching public exploits |
| Vulners Search | Advisories (CVE/vendor) for a product or CVE via Vulners (`VULNERS_API_KEY`) | Broader advisory coverage than NVD alone | Product / version or CVE ID | Related advisories and cross-references |

### 6.4 System (6) — local mode only, except where noted

| Tool | What it does | When you need it | Input | Output |
|---|---|---|---|---|
| Net Connections | Lists active connections and listening ports on the machine running the dashboard | Baseline of what is listening/connected right now | None (runs where the server is) | Listening + established connections table |
| Process Monitor | Running processes correlated with network activity | See which process owns which port | None (local system) | Process table with memory and port info |
| System Info | OS, interfaces, firewall, disk, RAM, security posture | One-screen picture of the box | None (local system) | System overview with a posture summary |
| PS Security Audit | Full Windows enterprise audit via PowerShell, 10 modules (system, users, processes, network, logs, files, registry, LOLBAS, drivers, hardware) | Deep internal audit of a Windows machine | None (Windows only; needs the Auditing_with_PowerShell repo cloned locally — see section 8) | Structured JSON per module with summaries |
| WiFi Marauder Scan | Polls the M5StickC Marauder viewer for scan data (networks, RSSI, BSSID, ESSID) | You have a Marauder on a shelf and want its scans in the dashboard | Viewer URL of your **local** Flask app, default `http://127.0.0.1:5000` | Networks table with signal strength and channels |
| M5Stick Networks | Polls WiFi networks + clients from the M5Stick Plus 2 Evil-M5Project viewer | Same, for a Plus 2 running Evil-M5Project | Viewer URL of your **local** Flask app, default `http://127.0.0.1:5000` | Networks with client counts and channels |

### 6.5 OSINT (12) — passive, mostly keyless

These look the target up in public sources instead of touching it. Most work without any API key; a few get better with a free key set on the *server* (`SHODAN_API_KEY`, `HUNTER_API_KEY`, `VULNERS_API_KEY`, `DNSDUMPSTER_API_KEY`, `GREYNOISE_API_KEY`).

| Tool | What it does | When you need it | Input | Output |
|---|---|---|---|---|
| ASN/BGP Lookup | ASN, BGP prefix and network operator for an IP/domain | Know who *owns* the network behind a host | Domain or IP | ASN, operator name, country |
| Reverse DNS | PTR records and the reverse-DNS chain | Map IPs back to hostnames; spot shared hosting | Domain or IP | PTR records, shared-hosting detection |
| CT Logs | Searches Certificate Transparency logs for the domain's certs | Find subdomains that never appear in DNS brute-force | Domain | Subdomains discovered via SSL certificates |
| Shodan Lookup | Ports, vulns, banners, tags (InternetDB free tier; full dsearch API with `SHODAN_API_KEY`) | Internet-wide view of an IP without touching it | Domain or IP | Open ports, CVEs, hostnames, OS |
| IP Geolocation | Geo, ISP, org, proxy/hosting detection | Quick "is this a datacenter, a VPN, a home line?" | Domain or IP | Country, city, ISP, proxy flag |
| Wayback URLs | Historical URLs of the domain from the Internet Archive (archive.org CDX) | Find pages that existed before and may still exist | Domain | Archived URL list |
| DNSDumpster Enum | Subdomain enumeration via dnsdumpster.com (`DNSDUMPSTER_API_KEY`, free account) | Second opinion on subdomains beyond the 81-name brute-force | Domain | Aggregated subdomain list |
| PublicWWW Search | Exposed URLs/hosts of a domain via publicwww.com (passive, no key) | Broad crawl-based inventory without scanning yourself | Domain | Hosts and URL samples |
| URLScan Lookup | Passive scan data (hosts) of a domain via urlscan.io search API (no key) | See what scanners have already observed | Domain | Scan results and hosts |
| GreyNoise Lookup | "Is this IP a known scanner?" via the GreyNoise community API (public; `GREYNOISE_API_KEY` raises the rate limit) | Triage: attacker noise vs real traffic | IP | Community classification (scanner/noise/...) |
| Hunter Email Finder | Known email addresses of a domain via Hunter Domain Search (`HUNTER_API_KEY`) | Build the org's email footprint for phishing-context or contact discovery | Domain | Found addresses with sources |
| Grep.app Code Search | Where a term (domain, email, token prefix) appears in public GitHub code | Find leaked references to your infra in public repos | Any search term | Matching public-code locations |

### 6.6 Email Security (3)

| Tool | What it does | When you need it | Input | Output |
|---|---|---|---|---|
| DNSSEC Checker | Verifies DNSSEC status and the chain of trust for a domain | Know whether your DNS can be spoofed by cache poisoning | Domain | DNSSEC status + chain findings |
| Email Security | SPF, DKIM and DMARC record analysis | The three records that decide if "your" mail is forgeable | Domain | Per-protocol results and what an attacker could do |
| DNS Zone Hygiene | SPF permissiveness, DKIM selector brute-force + key strength, DMARC policy, DNSKEY length | Deeper audit of the email-attacker's toolbox | Domain | Findings per control with severity |

### 6.7 RF Hardware (2) — offline capture analysis, no target needed

These two tools do **not** touch the network. You upload a file; the server analyzes it locally and stores it under `data/uploads/`. No internet access is required to run them.

**HackRF CFF Analyzer**
- Input: upload a `.cff` file (int8 I/Q interleaved, no header — the raw format HackRF One writes).
- What it does: characterizes the capture offline — DC offset, dominant tones, symbol timing, packet structure, sub-bursts, and FSK demodulation.
- Output: a characterization report of what the capture contains plus the FSK demod result. Use it to answer "what is on this signal?" before deciding which decoder to run.

**WiFi 802.11 Pcap Analyzer**
- Input: upload a `.pcap` / `.pcapng` (Marauder SD-card export or Wireshark capture).
- What it does: offline statistics over an 802.11 capture. Cap is 200,000 frames; larger files are truncated and the result is flagged as such.
- Output: a capture metadata table plus findings for each of these fields:
  - **SSIDs** seen in the capture, grouped per BSSID.
  - **Security buckets**: which networks were open / WPA / WPA2 / WPA3 / other.
  - **Channels** used, so you can see spectrum spread.
  - **Deauth activity**: deauthentication frames counted and attributed (a "deauth storm" finding means something is flooding deauths).
  - **WPS**: which networks had WPS enabled — flag them, WPS should be off.
  - **EAPOL 4-way handshake (M1-M4)**: detects a complete handshake in the capture. If one is found, the PSK/PMKID can be recovered *offline* from that file — treat captures containing handshakes as sensitive material and handle them like credentials.
  - **Hidden-SSID BSSIDs**: networks broadcasting with no SSID, listed by BSSID so you can correlate them with known gear.
  - **Client MAC list**: the client stations seen in the capture, for spotting rogue/extra clients on a network.

## 7. Pipelines: Fast / Deep / Full Depth / Nuclear

A pipeline is a named chain of tools that runs in phases. You pick mode + target; the UI shows per-phase, per-tool status live and you can cancel mid-run.

| Mode | Phases (tools inside) | Duration | Use it when |
|---|---|---|---|
| **Fast** | Recon (Whois, DNS Recon, HTTP Probe) → Scan (Port Scanner) | ~1 min | "Give me a quick picture of this target." |
| **Deep** | Recon (Whois, DNS, Subdomain Enum, HTTP Probe) → Scan (Port Scanner, SSL Analyzer) → Web (Headers, Tech, Dir Fuzz, CORS, CSP) → OSINT (Reverse DNS, CT Logs, Geo) | ~5 min | "I want the web-security story, not just ports." |
| **Full Depth** | Subdomains (Subdomain Enum) → Takeover (Subdomain Takeover) → Stack (Tech Detector) → CVE (CVE Correlation) → Secrets (Secret Leak Scan) | ~4 min | "Hunt for forgotten subdomains and what they leaked." |
| **Nuclear** | Recon (+CAA) → Scan → Web (10 tools incl. SQLi, XSS, Open Redirect, HTTP Methods, Robots) → Vuln (CVE Search) → OSINT (5 lookups) → Email (DNSSEC, Email Security) | ~7 min | "Full audit, everything we have." |

## 8. Hardware & audit tools: setup and why they are local-only

All three need no target domain/IP. They run **where the dashboard runs**, which is why remote deployments return 403 for them (section 2).

- **PS Security Audit** (Windows only): clone `https://github.com/PoisonXploIT/Auditing_with_PowerShell` to `~/Auditing_with_PowerShell`; the tool auto-detects the script. Run with admin privileges for full coverage (logs, registry, services).
- **WiFi Marauder Scan**: clone `https://github.com/PoisonXploIT/wifi-marauder-viewer`, run `python app.py`. Needs an M5StickC with Marauder firmware and a PuTTY serial log capture feeding the viewer.
- **M5Stick Networks**: clone `https://github.com/PoisonXploIT/Visualizacion_extendida_M5StickPlus2`, run `python src/app.py`. Needs an M5Stick Plus 2 running Evil-M5Project.

The "Viewer URL" field is the address of that Flask app **on your own computer** — typically `http://127.0.0.1:5000`. It is not a public URL and there is no public one: it must point at the box where the hardware sits, which is why this only works in local mode.

Splunk sourcetypes for these tools (section 9): `powershell:audit` (one event per audit module), `wifi:marauder` (one event with all detected networks: BSSID, ESSID, RSSI, channel), `m5stick:networks` (one event with networks + clients).

## 9. History, search and exports

- **History** has two tabs: *Scans* and *Pipelines*. Scans are paginated (50 per page) with Prev/Next.
- **Search** filters in real time by tool name, target name, target host or status.
- **View** opens formatted results: port tables, header grades, CVE cards — never a raw JSON dump. Pipeline views show each tool's output individually.
- **Target evolution**: in the Pipelines tab, click a target name or *Evol* to open the historical comparison: every run of that target in chronological order with score and findings count, a line chart of the 0-100 score across runs, and per-run deltas (findings new / fixed / persistent, matched by `finding_id`) that expand into severity + title.
- **Exports**:
  - *JSON (per scan/pipeline)* — Splunk-compatible format with `event`, `timestamp`, `target`, `result` fields. Ready for SIEM ingestion.
  - *JSON (Export All)* — bulk export of everything, single file with an `events[]` array. Use for backup or batch import into Splunk/ELK.
  - *PDF (per scan/pipeline)* — formatted report: metadata, results summary, raw JSON appendix. For documentation or sharing.
  - *PDF (Export All)* — full PDF report: summary, targets table, all scans and pipelines in tabular form.
  - *CSV* — one row per finding, for spreadsheets/SIEM (`/api/scans/{id}/export/csv` and the pipeline equivalent).

## 10. Webhooks (Discord / Slack / generic)

Get notified when runs finish without watching the dashboard.

1. *Webhooks* in the sidebar → *Add Webhook*: name, URL, type (**discord**, **slack**, or **generic**).
2. Pick events: `scan_complete`, `pipeline_complete`, or both.
3. Click *Test* to verify the URL before trusting it.

- **Discord**: Server Settings → Integrations → Webhooks → New Webhook; paste the URL, type "discord".
- **Slack**: Workspace → Apps → Incoming Webhooks → Add Configuration; paste the URL, type "slack".
- **Generic**: any HTTP endpoint that accepts POST with a JSON body. The payload carries `source`, `event`, `timestamp` and `data`.

## 11. Splunk auto-indexing

Automatic indexing of scan/pipeline results via the Splunk REST API: when enabled, every completed run sends a JSON event — no manual export.

1. *Splunk* in the sidebar.
2. Enter REST API URL (default `https://127.0.0.1:8089`), username, password, index name.
3. If Splunk uses a self-signed cert (typical locally), set **Verify SSL** to **No**.
4. *Save Settings* → *Test Connection*.
5. Set **Enable Auto-Indexing** to **Enabled**.
6. Use **Export All History** for the initial bulk sync of what already ran.

Event format: each event is JSON with `event`, `timestamp`, `scan_id`/`pipeline_id`, `tool`/`mode`, `target`, `status`, `success`, `elapsed_seconds`.

Tools with rich JSON output also send their **full results** under custom sourcetypes, so you can search the content, not just the completion event:

- `powershell:audit` — one event per audit module (system, users, processes, ...) for granular SPL searches.
- `wifi:marauder` — one event with all detected WiFi networks (BSSID, ESSID, RSSI, channel).
- `m5stick:networks` — one event with networks + clients (SSID, BSSID, client count).

SPL examples:

```spl
search index=sec_dashboard event="sec_dashboard_scan"
search index=sec_dashboard status="failed"
search index=sec_dashboard | stats count by tool
search index=sec_dashboard | timechart count
search index=sec_dashboard | stats avg(elapsed_seconds) as avg_time by tool

-- Hardware & audit tools:
search index=sec_dashboard sourcetype=powershell:audit
search index=sec_dashboard sourcetype=powershell:audit module=02_Usuarios
search index=sec_dashboard sourcetype=wifi:marauder
search index=sec_dashboard sourcetype=m5stick:networks
search index=sec_dashboard (sourcetype=wifi:marauder OR sourcetype=m5stick:networks) | table timestamp tool
```

Note: the Splunk REST API must be reachable **from the dashboard server**. Local use: both on the same machine. Remote deployment: Splunk must be reachable over the network.

## 12. Proxy / TOR / Cloudflare Tunnel

**Scanning through TOR:**

1. Install TOR Browser (torproject.org).
2. *Proxy* in the sidebar → select **TOR (SOCKS5)**, port **9150** → *Save*.
3. Click *Test TOR IP* to verify the connection.
4. Run your tools: OSINT and web tools route through TOR automatically.

System tools (`netstat`/`tasklist`) and the port scanner always use direct connections, not TOR — they inspect the local machine or need raw packets.

**SOCKS5:** any VPN that offers a SOCKS5 proxy (Mullvad, NordVPN, ...) works the same way: enter host/port in the Proxy page.

**Cloudflare Tunnel:** to expose a local dashboard with HTTPS without opening ports: `cloudflared tunnel --url http://localhost:8444`.

## 13. Security model in one page

- **SSRF protection (remote mode):** targets that resolve to private/loopback/link-local IPs, cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`), `localhost` variants and internal TLDs (`.internal`, `.local`, `.corp`, `.lan`, `.intranet`) are rejected; every rejection is logged as WARNING.
- **System & WiFi polling tools:** 403 in remote mode by design (section 2).
- **Rate limits:** 30 req/min per IP *and* per API key on scan/pipeline/target creation (the key bucket is keyed by a SHA-256 of the presented key, so the raw secret never sits in memory); 600 req/min on reads; `DELETE /api/reset` capped at 5 req/hour.
- **Reset protection:** `DELETE /api/reset` requires `?confirm=true` to stop accidental wipes from scanners/automation.
- **Auth:** API key on every `/api/*` (401 otherwise), lockout after repeated failures per peer, failed attempts logged with truncated keys; Cloudflare Access SSO as an outer layer on the public deployment.
- **Headers:** CSP, HSTS, `X-Content-Type-Options: nosniff`.
- **Uploads:** RF captures are analyzed offline and kept under `data/uploads/`; capped at 200,000 frames per capture.

---

*Generated from the in-app Guide plus `backend/config.py` (tool registry) — if a tool's behavior here disagrees with the code, the code wins; file an issue.*
