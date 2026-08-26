# SEC-DASHBOARD — Archivo de seguimiento (iteración por sesiones)

> Este archivo es el contexto oficial del proyecto entre sesiones. La próxima
> sesión DEBE empezar leyendo este archivo entero antes de tocar código.
> Su propósito es evitar compactación de contexto: cada sesión nueva arranca
> con el estado completo sin necesidad de re-explorar el proyecto.

---

## 1. Estado actual (resumen ejecutivo)

- **Proyecto**: sec-dashboard — dashboard de seguridad ofensiva/recon en Python puro.
- **Repo local**: `C:\Users\Sammi\sec-dashboard`
- **Repo remoto**: `https://github.com/PoisonXploIT/sec-dashboard.git` (origin, rama `master`)
- **Deploy productivo**: Railway, dominio `sec.sammideblas.com` (Cloudflare Access + API key).
- **Último commit**: `57057bf` — "fix(ssl-deep): DER cert fallback + prod smoke fixes"
- **Fecha del commit**: 2026-08 (sesión de Fase 0.4).
- **Estado del plan**: Fase 0 COMPLETA (0.1, 0.2, 0.3 y 0.4). Siguiente: Fase 1 — tools de profundidad.

### Comandos de referencia (siempre desde el repo)

```powershell
# Activar venv (ya tiene dependencias + pytest + ruff instalados)
.venv\Scripts\python.exe -m pytest -q          # suite completa (86 tests, ~0.7s, sin red)
.venv\Scripts\python.exe -m ruff check backend tests   # lint baseline E9/F82
.venv\Scripts\python.exe -m compileall -q backend      # compile check
git push origin master                        # dispara CI en GitHub
```

---

## 2. Qué es sec-dashboard

Dashboard de seguridad tipo "recon suite" con:

- **Backend**: FastAPI + SQLite (aiosqlite) + WebSockets + SPA en un solo HTML (`frontend/index.html`).
- **35 tools operativas** en Python puro (sin binarios externos), en `backend/tools/`:
  `network.py`, `web.py`, `vuln.py`, `system.py`, `osint.py`, `emailsec.py`, `audit.py`, `wifi.py`.
- **Pipeline engine** (`backend/pipeline.py`): 3 modos — `fast`, `deep`, `nuclear`.
- **Integración Splunk** (`backend/splunk.py`): export JSON con sourcetypes personalizados.
- **Proxy TOR** (`backend/proxy.py`), **auth API key** + Cloudflare Access, **SSRF protection** (`backend/validators.py`).
- **Exportes**: JSON y PDF (`backend/report.py`, fpdf2).
- **Auditoría reciente** (2026-08-17) documentada en `BUGS-AUDIT-2026-08-17.md` (fixes de SSRF, auth, errores, MalwareBazaar).

### Estructura clave del backend

| Archivo | Responsabilidad |
|---|---|
| `backend/main.py` | API FastAPI, endpoints de scans/pipelines/targets/export. Persistencia aquí. |
| `backend/config.py` | Registro de tools (`TOOLS`), categorías, `SPECIAL_TOOLS`, `PIPELINES`, rutas. |
| `backend/scanner.py` | Dispatcher `run_tool`/`run_parallel` → mapea tool_name a handler, timeouts, captura de errores. |
| `backend/pipeline.py` | Orquestador de pipelines (fases → tools en paralelo). |
| `backend/models.py` | Schema SQLite (`SCHEMA`) + `init_db` + `get_db`. |
| `backend/validators.py` | Validación de target / SSRF (modo local vs remoto). |
| `backend/report.py` | Exportes JSON (Splunk-compatible) y PDF (fpdf2, renderers por tool). |
| `backend/findings.py` | **NUEVO (Fase 0.3)**: modelo unificado de hallazgos + adapters + scoring. |
| `backend/splunk.py` | Auto-indexado a Splunk. |
| `backend/webhooks.py` | Notificaciones webhook. |
| `backend/proxy.py` | Cliente TOR. |

---

## 3. El plan de salto de calidad (hoja de ruta completa)

### Fase 0 — Fundamentos (imprescindible)
| # | Tarea | Estado |
|---|---|---|
| 0.1 | Suite de tests pytest (validators, scanner, report, config + tools críticas) | HECHO |
| 0.2 | CI con GitHub Actions (ruff + tests + compile) | HECHO |
| 0.3 | Modelo de hallazgo unificado `Finding` (severity, category, evidence, cve, confidence, remediation) | HECHO |
| 0.4 | Refactor salidas: tools devuelven findings[] además del JSON legible, sin romper UI | HECHO |

### Fase 1 — Tools de profundidad (diferenciador)

Estado por tarea (actualizar esta tabla al cerrar CADA sesión; la más avanzada marca el siguiente micro-paso):

| ID | Tool | Estado | Notas / fuentes |
|---|---|---|---|
| F1-CVE | Tech CVE Correlation | HECHO (`9551c44`) | Handler `cve_correlation` en tools/web.py: reutiliza `tech_detector`, extrae versiones del header Server, busca NVD por producto (top 8 techs) y marca CISA KEV. Adapter en findings.py: KEV = CRITICAL con campo `cve`, CVE critical/high = HIGH (medium/low descartados a propósito para no inflar el score). |
| F1-TAKEOVER | Subdomain Takeover | HECHO (`4454b14`) | Handler `subdomain_takeover` en tools/network.py: candidatos desde `ct_logs` (crt.sh, cap 50), resuelve CNAME con dnspython y sondea HTTP. Dangling = sin A record, inalcanzable o 404/503 contra `.github.io`/`.herokuapp.com`/S3 (`amazonaws.com`). Adapter: dangling = CRITICAL dedup por sub. |
| F1-SECRETS | Secret Leak Scanner | HECHO (`56cbc67`) | Handler `secret_leak_scan` en tools/web.py: known-path scanning — 18 rutas JS fijas + `/.git/HEAD` (+config y logs/HEAD como evidencia extra) + `/robots.txt`. Patterns TruffleHog-style sin dependencias (AWS, GitHub, Slack, Stripe, Google, private keys, tokens genéricos MEDIUM, débiles LOW); evidencia redactada. Adapter: `.git/` = CRITICAL, platform keys = HIGH, dedup por source+type+evidence, cap 20. **Desviación registrada**: las rutas `/wp-content/plugins|themes/**/*.js` del diseño quedaron fuera porque no son enumerables sin crawl; ver registro. |
| F1-SSL | SSL Deep Analyzer | HECHO (`ff6f79b` + fix `57057bf`) | Handler `ssl_deep_analyzer` en tools/network.py (stdlib-only ssl/socket): probes de TLS 1.0/1.1/1.2/1.3 con contextos restringidos por OP_NO_*, sondas de ciphers débiles (RC4/DES/3DES/NULL vía set_ciphers, solo reporta lo realmente negociado), HSTS por GET HTTP/1.0 crudo sobre TLS, OCSP stapling con ClientHello manual (ext status_request RFC 6066) y grade A+ a F por caps discretos. Reader ASN.1/DER puro como fallback cuando getpeercert() texto devuelve {} (CN subject/issuer, fechas, SAN, AIA OCSP). Smoke prod: A+ en sec.sammideblas.com. Adapter: legacy/weak-cipher/expired = HIGH, self-signed/no-PFS/HSTS ausente = MEDIUM, hsts_short/cert_expiring/ocsp = LOW. |
| F1-DNS | DNS Zone Hygiene | PENDIENTE | SPF permisivo (+all), DKIM selector brute, DMARC p=none, DNSKEY débil. |
| F1-FAVICON | Favicon/Stack Fingerprinting | PENDIENTE | Hashes de favicons + paths estáticos para versiones exactas. |

Reglas de ejecución por tool (repetir para cada ID):
1. Handler en el módulo Python adecuado bajo `backend/tools/` (patrón existente, sin binarios externos).
2. Registro en `config.py` (`TOOLS`, `HANDLERS` en scanner) — los tests de config lo validan solos.
3. Adapter `@register("tool_id")` en `findings.py` desde el día uno (findings/score ya viajan solos por pipeline/DB gracias a 0.4).
4. Tests sin red (stubs/monkeypatch, convención de la suite) — suite sigue verde antes de commit.
5. Commit con mensaje `feat: F1-<ID> ...`, push solo cuando la suite esté en verde; actualizar esta tabla y el registro de la sección 6.

### Fase 2 — Motor de severidad y scoring
- Scoring por target 0–100 (agregación de findings). Base ya lista: `score_findings()` en findings.py.
- Pipeline "Full Depth": subdomain_enum → takeover → tech_detector → cve_correlation → secret_leaks.
- Reporte ejecutivo PDF: portada con score, top 10 findings, heatmap por categoría, apéndice técnico.
- Comparativa histórica en History (evolución de un target entre scans).

### Fase 3 — Usabilidad y hardware
- 3E: CLI headless (`python -m backend.cli --target ... --pipeline nuclear --json`), dark mode persistente, búsqueda en History.
- 3A WiFi: `wifi_marauder_v6_scan`, `cyd_marauder_scan`, `evil_m5_cardcomputer_scan` (extiende patrón existente en wifi.py).
- 3B Bruce RF/BLE: `bruce_subghz_scan`, `bruce_nrf24_scan`, `bruce_ble_scan` (M5 Stick / CYD + CC1101/nRF24, viewer serial→HTTP).
- 3C Halehound + Flipper: `halehound_ble_scan` (serial o CSV), `flipper_subghz_import` (.sub), `flipper_nfc_import` (.nfc), `flipper_ir_import` (.ir), `flipper_wifi_marauder_scan`.
- 3D HackRF + Bus Pirate: `hackrf_capture_meta` (.c16), `hackrf_spectrum_log`, `bus_pirate_i2c_scan`, `bus_pirate_spi_scan`, `bus_pirate_uart_sniff`.
- Categorías nuevas: RF/SubGHz, Bluetooth/BLE, nRF24/2.4GHz, Hardware Bus, Files/Import.

### Fuera de alcance (decisión explícita)
- Multiusuario/roles (producto enterprise, no nicho).
- Agente distribuido en red interna.
- Herramientas de explotación activa (solo recon/pasivo por riesgo legal).

---

## 4. LO HECHO EN LA ÚLTIMA SESIÓN (Fase 0.1 + 0.2 + 0.3)

### Commit `788bde5` — 12 archivos, +823 líneas

```
.gitignore implícito (nada nuevo)
.github/workflows/ci.yml        NUEVO
backend/findings.py             NUEVO
pytest.ini                      NUEVO
requirements-dev.txt            NUEVO
ruff.toml                       NUEVO
tests/conftest.py               NUEVO
tests/test_validators.py        NUEVO
tests/test_config.py            NUEVO
tests/test_scanner.py           NUEVO
tests/test_report.py            NUEVO
tests/test_tools_vuln.py        NUEVO
tests/test_findings.py          NUEVO
```

### 4.1 Suite de tests (49 tests, ~0.6s, sin red)

| Archivo | Cubre |
|---|---|
| `tests/test_validators.py` (14) | SSRF local vs remoto: IP privada/loopback/link-local/metadata, localhost, TLDs internos, autodetección remota por `PORT`, IP pública siempre válida. |
| `tests/test_config.py` (6) | Coherencia de registro: HANDLERS ⊆ TOOLS, pipelines solo refieren tools registradas, SPECIAL_TOOLS ⊆ TOOLS, campos obligatorios en cada tool. |
| `tests/test_scanner.py` (6) | Tool desconocida → error; dispatch OK; excepción capturada SIN traceback al cliente (regla M1); timeout forzado (0.1s); run_parallel. |
| `tests/test_report.py` (6) | Roundtrip `generate_scan_json`, payload corrupto → `raw`, `generate_all_json` cuenta eventos, PDFs válidos (`%PDF`) con unicode y tool sin renderer. |
| `tests/test_tools_vuln.py` (7) | hash_checker (formato inválido, MD5 sin keys), password_audit offline (password123 = 4/11 Weak, fuerte, sin input, `_password_recommendations` pura). |
| `tests/test_findings.py` (10) | Serialización JSON, pesos de severidad ordenados, adapters (header/ssl/port/injection/cve), fallback INFO, fallback con adapter roto no lanza, scoring 0–100 acotado y monótono. |

Convenciones de la suite (respetarlas en tests nuevos):
- **Nunca hacer red**: stubs con monkeypatch. En vuln: `_OfflineSession` que lanza RuntimeError al construirse (fixture `offline` autouse).
- Usar `asyncio.run()` dentro de tests síncronos (evita dependencia pytest-asyncio).
- `monkeypatch.setitem(scanner.HANDLERS, ...)` / `scanner.TOOLS` para tools falsas (son el mismo dict importado).
- `tests/conftest.py` inserta el root del repo en sys.path.
- Config en `pytest.ini` (testpaths=tests, addopts=-q).

### 4.2 Modelo de hallazgo unificado — `backend/findings.py`

API pública:
- `Severity` enum: `CRITICAL/HIGH/MEDIUM/LOW/INFO` con `SEVERITY_WEIGHT` (10/7/4/2/0).
- `Finding` dataclass: `tool, category, severity, title, description, evidence, cve, confidence (0-1), remediation, target, finding_id, timestamp`. Método `to_dict()` → JSON-serializable (severity como string).
- `extract_findings(tool, result, target) -> list[Finding]`: despacha al adapter registrado; si no hay adapter → fallback INFO (o [] si result tiene error); si el adapter lanza → fallback, NUNCA rompe el pipeline.
- `score_findings(findings) -> int`: suma ponderada severidad × confidence, cap 100. Base para Fase 2.
- Registro de adapters vía decorador `@register("tool_id", ...)`.

Adapters ya implementados (9 tools):
| Tool | Hallazgos |
|---|---|
| header_analyzer | Header de seguridad ausente (HSTS = MEDIUM, resto LOW) + information leakage (LOW) |
| ssl_analyzer | TLS legado/SSL (CRITICAL/HIGH), cipher débil RC4/DES/3DES/NULL (HIGH), cert inválido (MEDIUM) |
| port_scanner | Puertos sensibles: 22, 3389, 3306, 5432, 27017, 6379, 8080 (MEDIUM) |
| cors_checker | Misconfiguración CORS (MEDIUM) |
| sqli_scanner / xss_scanner | Hallazgos de inyección (HIGH, confianza 0.7) |
| open_redirect | Open redirect (MEDIUM) |
| cve_search | Mapea severity NVD → Severity, incluye `cve` id |
| tech_detector | INFO informativo (stack) — pensado para alimentar CVE correlation en Fase 1 |

### 4.3 CI — `.github/workflows/ci.yml`

- Disparo: push a main/master + pull requests.
- Pasos: checkout → setup-python 3.12 → `pip install -r requirements.txt -r requirements-dev.txt` → `ruff check backend tests` → `python -m compileall -q backend` → `python -m pytest -v`.
- `ruff.toml`: baseline `select = ["E9", "F82"]` (bugs reales: sintaxis, nombres indefinidos). El código base tiene ~237 avisos preexistentes con el ruleset por defecto; el baseline es intencionado y se puede ampliar progresivamente.
- `requirements-dev.txt`: `pytest>=8.0`, `ruff>=0.5`.

### 4.4 Decisiones tomadas en esta fase

1. Ruff con baseline E9/F82 (no romper CI con deuda preexistente).
2. Tests síncronos con `asyncio.run()` (sin pytest-asyncio).
3. `extract_findings` con fallback a prueba de errores (un adapter roto jamás rompe un scan).
4. El módulo findings NO toca `scanner.run_tool` todavía — eso es la Fase 0.4.

---

## 5. LO HECHO EN LA SESIÓN DE FASE 0.4 + SIGUIENTE PASO

### Commit `bd5521e` — Fase 0.4 completa (6 archivos, +344 líneas)
- `scanner.run_tool`: `findings[]` + `score` en TODAS las salidas (OK, timeout, error, tool desconocida). UI sigue consumiendo `result` intacto.
- `pipeline.py`: findings por tool preservados en cada fase + lista agregada y score total al final (`score_finding_dicts`).
- `models.py` / `main.py`: columnas `findings TEXT` + `score INTEGER` en `scans` y `pipelines`, con migration automática en startup para DBs existentes (patrón RENAME TO *_old).
- `main.py`: helpers `_persist_scan_result` / `_persist_pipeline_result`; redacción M4 extendida a los targets dentro de findings.
- `findings.py`: `score_finding_dicts()` para dicts serializados.
- `tests/test_fase04_findings.py`: 6 tests nuevos (55 en total). Sin red; persistencia probada contra una DB descartable en tmp_path vía monkeypatch de `models.DB_PATH`.

Decisiones pendientes resueltas según lo recomendado: score guardado en DB (`score INTEGER`, ordenable en History) y el pipeline guarda AMBOS — findings por tool en cada fase y la lista agregada + score total.

### Siguiente paso — Fase 1 (tools de profundidad)
Prioridad del plan: **Tech CVE Correlation** y **Subdomain Takeover** primero; luego Secret Leak Scanner, SSL Deep Analyzer, DNS Zone Hygiene y Favicon/Stack Fingerprinting. Regla desde el día uno: cada tool nueva registra su adapter en `findings.py` (patrón `@register("tool_id")`) para que findings/score funcionen sin tocar el pipeline.

---

## 6. Registro de ejecuciones (append-only)

Convención: cada sesión añade una entrada al FINAL de la lista (la más reciente abajo), con fecha, commits, qué se hizo y el siguiente micro-paso. No reescribir entradas antiguas; si algo cambia, añadir nota nueva.

### 2026-08-17 — Auditoría + fixes base
- Commits `724c205` hasta `1563544`: SSRF (C1), auth API key/Cloudflare Access (C2), M1 sin tracebacks, M2 MalwareBazaar, M3 race, M4 redacción, L1-L4 UX.
- Documentado en `BUGS-AUDIT-2026-08-17.md`.

### 2026-08-26 — Fase 0 (tests + modelo Finding + CI)
- Commit `788bde5`: suite pytest (49 tests), `backend/findings.py` (9 adapters), CI ruff+pytest.
- Siguiente micro-paso: tarea 0.4.

### 2026-08-26 — Fase 0.4 completa (sesión interrumpida por apagón, recuperada sin pérdidas)
- Apagón en mitad de 0.4: el código quedó íntegro en working tree sin commit; se recuperó leyendo este archivo.
- Commits `bd5521e` (feat 0.4: findings/score en scanner, pipeline agregado, migración DB, persistencia) y `ba2d333` (docs). Push a origin/master hecho; CI + Railway desplegados a sec.sammideblas.com.
- Suite: 55 tests en verde, ruff limpio.
- Siguiente micro-paso: arrancar Fase 1 por F1-CVE (Tech CVE Correlation).

### 2026-08-26 — F1-CVE completa (Tech CVE Correlation)
- Commit `9551c44`: tool `cve_correlation` (tools/web.py) + registro en config/scanner + adapter findings + 9 tests nuevos (64 en total, sin red: stubs de `tech_detector`, `_nvd_product_search`, `_fetch_kev`).
- Decisiones: top 8 techs buscadas en NVD con filtro client-side por palabra del producto; KEV feed vía raw.githubusercontent (fallos de fuente no rompen el scan, se devuelve lo que haya); sorting KEV primero y luego CVSS desc.
- Siguiente micro-paso: F1-TAKEOVER (Subdomain Takeover).

### 2026-08-26 — F1-TAKEOVER completa (Subdomain Takeover)
- Commit `4454b14`: tool `subdomain_takeover` (tools/network.py) + registro en config/scanner + adapter findings + 11 tests nuevos (75 en total, sin red: stubs de `ct_logs`, `_takeover_dns`, `_takeover_probe`).
- Decisiones: candidatos = subdominios de CT logs (crt.sh, cap 50, root excluido); plataforma por sufijo/regex del CNAME (github.io/githubpages.dev, herokuapp/onheroku, s3 + website amazonaws con regions); dangling si no hay A record, el probe falla o responde 404/503; fallo de crt.sh degrada a `ct_error` sin romper el scan.
- Commit `4870087`: docs de SEGUIMIENTO post-F1-TAKEOVER.
- Siguiente micro-paso: F1-SECRETS (Secret Leak Scanner). Diseño fijado: known-path scanning para JS; crawl limitado queda fuera del MVP (ver nueva entrada en registro).

### 2026-08-26 — F1-SECRETS: decisión de diseño fijada en SEGUIMIENTO
- No se tocó código. Se resolvió la duda de diseño pendiente para el scanner de secrets.
- Decisión: en el MVP el scan de JS se hace contra **rutas conocidas** (known-path), NO con crawl limitado.
- Razón: menor complejidad, predictibilidad, tests sin red más simples y cubre la mayoría de casos reales. El crawl limitado se deja como mejora futura (Fase 2/3) si la evidencia lo justifica.
- Alcance inicial de rutas JS: `/main.js`, `/app.js`, `/bundle.js`, `/vendor.js`, `/common.js`, `/site.js`, `/scripts/*.js`, `/js/*.js`, `/static/js/*.js`, `/assets/js/*.js`, `/wp-content/plugins/**/*.js`, `/wp-content/themes/**/*.js`.
- Fuentes adicionales obligatorias: `/.git/HEAD` (y opcionalmente `config`, `refs/heads/master`, `index`, `logs/HEAD`), `/robots.txt`.
- Severidad propuesta: `.git/` expuesto = CRITICAL; API keys/tokens de plataformas de alto impacto (AWS, GitHub, Slack, Stripe, etc.) = HIGH; tokens genéricos o keys en JS/robots.txt = MEDIUM; matches débiles = LOW. Dedup por `finding_id` combinando tipo + target + evidencia normalizada.
- Nota: los regexs serán estilo TruffleHog/TruffleHog3 sin dependencias externas; solo patterns con alta confianza en el MVP.

### 2026-08-26 — F1-SECRETS completa (Secret Leak Scanner)
- Commit `56cbc67`: tool `secret_leak_scan` (tools/web.py) + registro en config/scanner + adapter findings + 11 tests nuevos (86 en total, sin red: stub de `_secret_fetch`).
- Implementado: 18 URLs JS fijas (raíz + `/scripts/`, `/js/`, `/static/js/`, `/assets/js/` × main/app/bundle.js), `/.git/HEAD` con `config` y `logs/HEAD` como evidencia extra, `/robots.txt`. Patterns de alta confianza: AWS (`AKIA|ASIA|A3TQ`+16), GitHub (`gh[pousr]_`, `github_pat_`), Slack (`xox[baprs]-`), Stripe (`sk_live_`, `whsec_`), Google (`AIza`+35), private keys, tokens genéricos (MEDIUM) y matches débiles tipo password= (LOW). Evidencia redactada (`prefijo***(len)`) para no almacenar el secreto completo. Un solo match por fuente (first-match-wins por severidad de patrón).
- Adapter: `.git/` expuesto = CRITICAL, platform keys = HIGH, genéricos MEDIUM, débiles LOW; dedup por source+type+evidence redactada; cap 20.
- **Desviación del diseño fijado (requiere revisión)**: las rutas `/wp-content/plugins/**/*.js` y `/wp-content/themes/**/*.js` NO se implementaron porque no son enumerables sin crawl (los nombres de plugin/tema varían por sitio) y el crawl quedó fuera del MVP. Quedan como mejora futura junto al crawl limitado. Si se quiere cubrir en Fase 2, la vía natural es un GET de la home para extraer `script src` reales.
- Siguiente micro-paso: F1-SSL (SSL Deep Analyzer).

### 2026-08-26 — F1-SECRETS aprobado + refactor backlog (cierre de sesión)
- Aprobado por el usuario: la deferral de `/wp-content/plugins|themes/**/*.js` es correcta (no son known-paths fijas; necesitan crawl o parsear `script src` de la home, fuera del MVP) y la solución al incidente de push protection (token fake construido por partes) fue la correcta.
- Refactor pendiente de F1-SECRETS (no bloqueante, hacer al pulir la tool):
  1. `_secret_fetch` crea un `aiohttp.ClientSession` por URL (~22 requests/scan): hoisting de una sola sesión fuera del gather y pasarla a cada fetch.
  2. `_scan_text` hace return tras el primer match: un archivo con varios secretos solo reporta uno. Cambiar `search` → `finditer` y deduplicar por posición.
- Nota para F1-SSL: `cryptography` NO está en requirements.txt ni requirements-dev.txt; el MVP va stdlib-only (`ssl`/`socket`). Si OCSP/HSTS o grades la requieren, añadir dependencia es una decisión a registrar antes de instalarla.
- Siguiente micro-paso: F1-SSL (SSL Deep Analyzer) — grade A+ a F, cipher suites, TLS 1.0/1.1, HSTS, OCSP stapling.

### 2026-08-26 — F1-SSL completa (SSL Deep Analyzer)
- Commit `ff6f79b`: tool `ssl_deep_analyzer` (tools/network.py) + registro en config/scanner + adapter findings + 17 tests nuevos (103 en total, sin red: stub de `_ssl_deep_scan_blocking`, parser OCSP alimentado con registros sintéticos).
- Implementado (stdlib-only, sin dependencias nuevas): sondas de versión TLS 1.0/1.1/1.2/1.3 con `SSLContext` restringido por flags `OP_NO_*`; ciphers débiles por familia (RC4, DES-CBC, 3DES, NULL) con `set_ciphers`, solo se reporta si el handshake realmente lo negoció; HSTS leyendo el header de una petición HTTP/1.0 cruda sobre TLS (max-age, includeSubDomains, preload); OCSP stapling enviando un ClientHello construido a mano con SNI + extensión `status_request` (RFC 6066) y parseando el ServerHello en bruto ("yes" si trae `status_response`, "no" si no, "unknown" si timeout/alerta); certificado sin verificación (self-signed, expirado, días restantes, SAN, OCSP responder).
- Grade A+ a F por caps discretos: tls_legacy fail = F, weak_cipher fail = F, cert_expired fail = D, self_signed fail = C, no_forward_secrecy fail = B+, hsts_missing fail = A, hsts_short (<180d) fail = A-. El peor cap gana.
- Decisiones: (1) best-effort declarado — si el OpenSSL local no puede negociar TLS 1.0/1.1 o rechazar un cipher string, la sonda se marca como no soportada/no testeable y NUNCA se reporta un cipher débil no negociado; (2) OCSP "unknown" es legítimo (no penaliza el grade): la check `ocsp_unavailable` solo avisa cuando ni stapling ni responder están disponibles; (3) si ninguna conexión TLS tiene éxito el handler devuelve error limpio (patrón ssl_analyzer) y el adapter no emite findings.
- Siguiente micro-paso: F1-DNS (DNS Zone Hygiene).

### 2026-08-26 — F1-SSL: smoke prod, 2 bugs reales y reader DER (fix 57057bf)
- Smoke en prod (`ssl_deep_analyzer('sec.sammideblas.com')`) reveló 2 bugs: (1) `weak_ciphers` reportaba TLS_AES_256_GCM_SHA384 — `set_ciphers` no restringe la oferta TLS 1.3, así que los contextos "RC4" ofrecían suites 1.3 por defecto; fix: pin de `OP_NO_TLSv1_3` en el contexto de sondas + `_classify_weak_cipher(name)` que mapea el nombre negociado a familia débil (NULL/RC4/3DES/DES, 3DES antes que DES por substring). (2) PFS falso positivo con TLS 1.3: `has_pfs` ahora acepta version startswith "TLSv1.3" (PFS nativo, sin Kx en el nombre).
- `days_left: None`: en este build (Python 3.12.10 / OpenSSL 3.0.16 Windows) `getpeercert()` texto devuelve {} con contexto CERT_NONE (funciona sí con verificación). DER siempre disponible. Solución: reader ASN.1/DER puro (`_der_tlv`, `_parse_name_cn`, `_parse_cert_der`, `_cert_facts`) — subject/issuer CN, notBefore/notAfter, SAN, AIA OCSP responder; merge texto+DER en `_probe_certificate`.
- Bugs del reader cazados por tests: offset del serial INTEGER tras versión explícita (v3/v2); OIDs reconocidos por byte-exact compare (SAN `55 1D 11`, AIA `2B 06 01 05 05 07 30 01`, CN `55 04 03`) — se eliminó el decoder base-128 roto; GeneralName: el contenido del `[2]/[6] EXPLICIT` YA es el TLV IA5String (un desempaquetado menos, no uno más); helper de tests `_t` escribía cabecera long-form con byte extra (`30 82 02 00 ...` → `30 82 00 xx`); `not_before` sin fallback DER en el merge.
- Verificado contra certs reales (github.com: SAN thub.com/w.github.com, issuer Sectigo; prod CF: YE1, SAN sammideblas.com/mmideblas.com, days_left 60).
- Suite: 115 tests en verde, ruff limpio. Smoke final prod: grade A+, weak_ciphers=[], único finding LOW `ocsp_unavailable` (esperado: CF sin stapling ni AIA).
- Observaciones del usuario (NO bloqueantes, aparcadas): (1) perf — probes TLS 1.0/1.1/1.2/1.3 + ciphers en serie; (2) HRR edge case no cubierto por tests; (3) HSTS sin seguir redirects (el GET crudo no sigue 301/302); (4) backlog refactor F1-SECRETS pendiente.
- Decisión de la sesión: ANTES de arrancar F1-DNS, hacer el pase rápido de refactor de F1-SECRETS (~30 min): session compartida en `_secret_fetch` (hoy ~22 requests/scan con una session por URL) y `search` → `finditer` + dedup por posición en `_scan_text`. Después, F1-DNS.

### 2026-08-26 — Pase rápido de refactor F1-SECRETS (cierre del backlog de 56cbc67)
- Commit `93b0fe9`: sin cambios de comportamiento operativo, solo los dos puntos del backlog.
  1. Session compartida: `_secret_fetch(url, session)` ya no crea `ClientSession`; la abre una sola vez `secret_leak_scan` (hoistada fuera del `gather`) y la pasa a los ~22 fetchs. Timeout total=8.0 por request viaja en la session.
  2. `_scan_text`: `search` → `finditer`; un archivo con varios secretos ahora los reporta todos. Dedup por posición: dos patterns cuyo span se solapan (p. ej. `password = "AKIA..."` cae en `aws_access_key_id` y en `weak_match`) se reportan una sola vez, gana el pattern que aparece primero en la tabla (tier alto antes que bajo).
- Tests: 5 nuevos (120 en total, sin red) — un solo `_FakeSession` construido para todas las URLs (el `_secret_fetch` real corre contra él), fetch con excepción degradando a not-found sin romper el scan, archivo con dos secretos de plataformas distintas, dedup por posición, texto limpio.
- Sin dependencias nuevas; `cryptography` sigue sin estar registrada (MVP stdlib-only intacto).
- Siguiente micro-paso: F1-DNS (DNS Zone Hygiene).

### 2026-08-26 — F1-DNS completa (DNS Zone Hygiene)
- Commit `145e9a3`: tool `dns_zone_hygiene` (tools/emailsec.py) + registro en config/scanner + adapter findings + 16 tests nuevos (136 en total, sin red: stubs de `_hygiene_txt`/`_hygiene_dnskey`).
- Implementado (dnspython ya estaba en requirements desde F1-TAKEOVER; sin dependencias nuevas): SPF (TXT apex) — `+all` = HIGH, múltiples v=spf1 = MEDIUM, sin `-all` terminal = LOW, ausente = MEDIUM; DMARC (`_dmarc.`) — ausente = MEDIUM, `p=none` = MEDIUM, `sp=` más débil que `p=` = LOW, `pct<100` con quarantine/reject = LOW; DKIM — brute de 13 selectores comunes en paralelo (gather), sin key = MEDIUM, key vacía = LOW, RSA <1024 bits = HIGH, 1024–2047 = LOW; DNSKEY (apex) — RSA <1024 = HIGH, 1024–2047 = LOW, ECDSAP256 (alg 5) = 256 bits.
- Fuerza de clave: SPKI DER propio (`_spki_key_bits`: OID rsaEncryption → longitud exacta del MPI; ecdsa-with-SHA256 → P-256 por RFC 6945) para el `p=` de DKIM; `_dnskey_bits` sobre el campo Public Key del RDATA (MPI base-128 para alg 1/3). Unknown → nunca se marca débil.
- Best-effort: cada query devuelve status (`ok`/`nxdomain`/`noanswer`/`error`); las conclusiones de "missing" solo salen con respuesta definitiva, NUNCA por timeout; apex NXDOMAIN → error limpio (patrón caa_checker); IP → error.
- Siguiente micro-paso: Phase 2 (Full Depth pipeline) — ver PLAN.md.

## 7. Reglas y restricciones del proyecto (NO VIOLAR)

1. **NO emojis, flechas de texto ni símbolos de color** en ninguna salida, nota, script o commit (regla global del usuario). Escribir las palabras.
2. **Local-first**: priorizar herramientas/skills locales; el modelo se queda local; solo APIs externas como fuentes de datos (NVD, CISA KEV, HIBP, MalwareBazaar, etc.).
3. **M1**: los tracebacks se logean server-side, NUNCA al cliente (ya cubierto por tests).
4. **Solo recon/pasivo**: nada de explotación activa ni jamming (legal).
5. **Hardware**: puedo escribir todo el software (viewers, polling, importes, watchers de carpeta, sourcetypes), pero los parsers de serial/formatos (Bruce serial, .sub/.nfc/.ir, .c16) necesitan **capturas reales del usuario** para validarse.
6. **Sin multiusuario/roles** (fuera de alcance deliberado).
7. Los tests NUNCA deben depender de red; usar stubs/monkeypatch.
8. Push a origin/master dispara CI y, vía Railway, deploy a sec.sammideblas.com — confirmar con el usuario antes de push cuando haya dudas (esta vez ya está confirmado).

---

## 8. Referencias

- Documentación en `C:\Users\Sammi\Documents\Destino\PROYECTOS\SEC-DASHBOARD\`:
  - `Plan de Mejora y Expansión.md` (el plan original completo, con tablas de hardware)
  - `sec-dashboard - Project Overview.md`
  - `sec-dashboard - Guia de uso.md`, `Manual Rapido.md`, `Guia novato.md`
  - `sec-dashboard - Integracion Hardware y Splunk Export.md`
  - `sec-dashboard - Integracion Auditing with PowerShell.md`
  - `sec-dashboard - Auditoria Fixes y Tests (2026-08-17).md`
- En el repo: `README.md`, `BUGS-AUDIT-2026-08-17.md`, `Dockerfile`, `docker-compose.yml`, `start.bat`.

### Hardware disponible (resumen para integración futura)
M5 Stick + CC1101 + nRF24 (Bruce), WiFi Marauder ESP32 v6, LilyGo T-Embed + Bus Pirate, Halehound en CYD 2.8" capacitiva, CYD 3.5" (Marauder), CYD 2.8" (Bruce), CardComputer M5Stack (Evil M5), ATOM MS3R (sin caso claro de uso — opción: botón físico de lanzamiento de scans), HackRF PortaPack H4, Flipper Zero (stock + posible WiFi Devboard).

---

*Última actualización: 2026-08-26, post-F1-DNS `145e9a3` (suite 136 tests en verde; ruff limpio). Próxima sesión: Phase 2 Full Depth pipeline — ver PLAN.md.*
