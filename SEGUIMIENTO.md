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
- **Último commit de código**: `6df6c70` (rate limiting in-memory, cola paso 1) tras `c728d3d` (fix badge tools-count) + docs de cierre.
- **Fecha del commit**: 2026-08-26.
- **Estado del plan**: Fase 1 COMPLETA de verdad (F1-FAVICON `912676b`). **Fase 2 COMPLETA**: Full Depth pipeline (`a0cf16a`), reporte ejecutivo PDF (`10ed28f`), comparativa histórica en History (`165af5d`). **Fase 3 / 3E CERRADA**: sub-micro-pasos 1 (CLI headless, `3da329e`), 2 (modo light dedicado, `6f230b0`) y 3 (búsqueda en History, `85f51f3`) completos. **CLI enrichment completa** (`8ef2853`): `--tool TOOL_ID --target HOST` (run_tool directo), `--list-tools`, `--list-pipelines`, mutua exclusión `--tool`/`--pipeline`. **Cola de micro-pasos fijada por el usuario** (2026-08-26, antes de hardware/TUI): rate limiting → paginación server-side → F1-FAVICON → export CSV → logging estructurado; luego hardware/TUI con capturas reales. **Rate limiting COMPLETO** (`6df6c70`); **paginación server-side COMPLETA** (`e528101`); **F1-FAVICON COMPLETA** (`912676b`); siguiente export CSV.

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
- **40 tools operativas** en Python puro (sin binarios externos), en `backend/tools/`:
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
| F1-DNS | DNS Zone Hygiene | HECHO (`145e9a3` + fix `3fdbcfe`) | Handler `dns_zone_hygiene` en tools/emailsec.py (dnspython, ya registrada): SPF (+all HIGH, múltiples v=spf1 MEDIUM, sin -all terminal LOW, ausente MEDIUM), DMARC (ausente/p=none MEDIUM, sp débil y pct<100 LOW), DKIM brute de 13 selectores con fuerza de clave SPKI propia (RSA <1024 HIGH, 1024–2047 LOW, P-256 por OID RFC 6945), DNSKEY (MPI del Public Key; ECDSAP256=256). Best-effort: "missing" solo con respuesta definitiva (ok/noanswer), nunca por timeout. Fix `3fdbcfe`: SPKI real de RFC 5280 (el parser ahora recorre RSAPublicKey hasta el INTEGER modulus; antes leía el blob entero, 1024→1134 bits). |
| F1-FAVICON | Favicon/Stack Fingerprinting | BACKLOG (Fase 2/3) | Decisión Opción A del 2026-08-26: se salta para arrancar Phase 2; hashes de favicons + paths estáticos, reanudar si el pipeline lo justifica. |

Reglas de ejecución por tool (repetir para cada ID):
1. Handler en el módulo Python adecuado bajo `backend/tools/` (patrón existente, sin binarios externos).
2. Registro en `config.py` (`TOOLS`, `HANDLERS` en scanner) — los tests de config lo validan solos.
3. Adapter `@register("tool_id")` en `findings.py` desde el día uno (findings/score ya viajan solos por pipeline/DB gracias a 0.4).
4. Tests sin red (stubs/monkeypatch, convención de la suite) — suite sigue verde antes de commit.
5. Commit con mensaje `feat: F1-<ID> ...`, push solo cuando la suite esté en verde; actualizar esta tabla y el registro de la sección 6.

### Fase 2 — Motor de severidad y scoring
- Scoring por target 0–100: HECHO. `score_findings()` en findings.py; persistido en DB desde Fase 0.4.
- Pipeline "Full Depth": HECHO (`a0cf16a`). Modo `full_depth` en `PIPELINES`: 5 fases secuenciales, una tool por fase (subdomain_enum, subdomain_takeover, tech_detector, cve_correlation, secret_leak_scan); card + mapas JS en UI; test que pinta la cadena (`test_full_depth_pipeline_chain`).
- Reporte ejecutivo PDF: HECHO (`10ed28f`). `generate_executive_pdf` en report.py (portada con score grande grayscale por umbrales 60/30, top 10 por peso de severidad x confidence, heatmap categoría x severidad celdas grayscale, apéndice técnico por fase/tool + JSON comprimido); helpers puros `executive_findings_from_pipeline` / `executive_top_findings` / `executive_heatmap`; endpoint `/api/pipelines/{id}/executive-pdf` + botón "Exec" en 3 sitios de la UI. El PDF técnico (`generate_pipeline_pdf`) se conserva intacto.
- Comparativa histórica en History (evolución de un target entre scans): HECHO (`165af5d`). Endpoint `GET /api/pipelines/compare?target_id=N` con la query exacta del diseño (runs con `findings_count` y `score` parseados, 404 si el target no existe, filas legacy NULL/JSON corrupto toleradas) + vista de evolución en History: tabla cronológica (run/modo/fecha/findings/score) + sparkline canvas 0-100 sin librerías nuevas; botón **Evol** en la tabla de pipelines y en `viewPipelineResult`, target clicable. SIN delta de findings en el MVP: new/fixed/persistent por `finding_id` entre runs adyacentes = micro-paso opcional (3b). Cerrado el bug cosmético del sidebar: contador tools/categorías ahora dinámico desde `/api/tools`.

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
- Siguiente micro-paso: Phase 2 (Full Depth pipeline) — ver sección Fase 2 de este archivo.

### 2026-08-26 — Revisión F1-DNS: fix SPKI real-world + decisión de ruta (Opción A)
- Fix `3fdbcfe` (revisión del usuario): `_spki_key_bits` leía el contenido del BIT STRING completo como número; en un SPKI real de RFC 5280 ese campo contiene RSAPublicKey SEQUENCE {modulus, exponent}. Un vector realista RSA-1024 devolvía 1134 bits → una key real de 1024 caía en legacy (LOW) en vez de weak (HIGH). Ahora recorre la SEQUENCE y lee el INTEGER modulus. Los tests ahora construyen SPKI estándar (antes usaban MPI crudo, que pasaba por casualidad); `_dnskey_bits` verificado OK contra dnspython (`r.publickey` ya es el campo Public Key crudo) y su docstring quedó aclarada (big-endian two's-complement = el base-128 MPI de RFC 4034).
- Suite 136 en verde, ruff limpio.
- Decisión de ruta (Opción A, la recomendada): F1-FAVICON pasa a backlog opcional de Fase 2/3 y se arranca Phase 2 Full Depth pipeline. Queda registrada para que la próxima sesión no tenga que releer el plan.

### 2026-08-26 — Bug cosmético registrado (sidebar: contador de tools)
- El sidebar derecho muestra "35 tools • 6 categories" hardcodeado en `frontend/index.html` (línea ~341), pero `backend/config.py` registra **40** tools. El número no se actualiza al añadir tools nuevas.
- Mínimo y cosmético, NO bloqueante; decisión del usuario: no tocar ahora, que no se olvide.
- Fix sugerido para el pase de pulido (o dentro de Phase 2 si se toca la UI): o bien contar dinámicamente desde `/api/tools` al renderizar el sidebar, o actualizar el literal a 40 + categorías reales. Si se hace en Phase 2, commit `fix:` y suite verde antes de push.

### 2026-08-26 — Phase 2 arranca: Full Depth pipeline + reporte ejecutivo PDF
- Commit `a0cf16a`: modo `full_depth` en `PIPELINES` (5 fases secuenciales, una tool por fase, todos handlers existentes; findings/score fluyen solos por Fase 0.4). Card "Full Depth" en UI + entradas en los 2 mapas JS hardcodeados. Test nuevo que pinta la cadena exacta del plan. Suite 137 en verde.
- Commit `10ed28f`: reporte ejecutivo PDF según diseño aprobado por el usuario: (1) `generate_executive_pdf(pipeline, target)` NUEVO, sin reescribir `generate_pipeline_pdf`; (2) portada "Executive Report" con score grande 0-100 y relleno grayscale por umbrales (>=60 oscuro / >=30 medio / <30 claro; n/a si falta); (3) top 10 findings ordenados por peso de severidad x confidence descendente (severity, category, title, description truncado, evidence resumido); (4) heatmap categoría x severidad (CRITICAL/HIGH/MEDIUM/LOW/INFO) con conteos y celdas rellenas grayscale por intensidad; (5) apéndice técnico: resumen por fase/tool (OK/FAIL, elapsed, n findings) + bloque JSON comprimido. Helpers puros testables: `executive_findings_from_pipeline` (fallback [] / None si result falta o esta roto), `executive_top_findings`, `executive_heatmap`. Endpoint `/api/pipelines/{id}/executive-pdf` en main.py (mismo patron que export/pdf) + boton "Exec" en history, viewPipelineResult y filteredPipelines + fila en la tabla de endpoints. Tests: 6 nuevos con extractor de texto PDF real (zlib sobre streams Flate) — %PDF, score "72/100" y target presentes, CRITICAL antes que LOW, conteos del heatmap, fallback n/a. Suite 143 en verde, ruff limpio, compileall OK; smoke 30 findings con saltos de pagina OK.
- Decisiones: escala solo grayscale (regla no emojis/simbolos de color estricta); top 10 con confidence por defecto 1.0 si falta; categoria vacia = "uncategorized"; el PDF tecnico sigue disponible como antes (los dos conviven).
- Siguiente micro-paso: comparativa historica en History (evolucion de un target entre scans). Mantener visible el bug cosmetico del sidebar (35 tools hardcodeadas vs 40 reales) para el pase de pulido.

### 2026-08-26 — Comparativa histórica: diseño aprobado (arranque, cierre de Phase 2)
- Validación previa del usuario: 143 passed, ruff limpio, compileall OK, master == origin/master @ `b4d8cc9`, working tree limpio.
- Decisión: arrancar la comparativa histórica como cierre natural de Phase 2; los datos ya están listos (columnas `score` y `findings` en la tabla `pipelines` desde Fase 0.4, ver `_persist_pipeline_result`).
- Enfoque aprobado (recomendación opción 1): **endpoint dedicado** `GET /api/pipelines/compare?target_id=N`. Query: `SELECT id, mode, score, findings, started_at, finished_at FROM pipelines WHERE target_id = ? ORDER BY started_at ASC`. Devolver lista de runs con `findings_count` y `score` parseados. **SIN delta de findings en el MVP** (new/fixed/persistent comparando `finding_id` entre runs adyacentes): queda como micro-paso 3b opcional si el endpoint base queda limpio.
- Frontend: vista History mejorada — al hacer clic en un target o en una fila de pipeline, tabla de evolución (runs con score, fecha, modo) + mini gráfico de líneas simple con `<canvas>` o sparkline ASCII para evitar librerías nuevas. Bonus (3b): listado de findings que aparecieron/desaparecieron entre la run actual y la anterior.
- Alternativa descartada para el MVP: extender `/api/pipelines/history` con `?target_id=` y filtrar en frontend (menos trabajo backend, más frontend) — se prefiere el endpoint dedicado por limpieza.
- Tests: 2-3 tests del endpoint con 2-3 pipelines para el mismo target verificando orden cronológico y score, con DB temporal (monkeypatch de `models.DB_PATH`, patrón Fase 0.4 en tests/test_fase04_findings.py).
- Siguiente micro-paso: implementar ese diseño (endpoint + tabla evolutiva), commit `feat:`, suite verde antes de push.

### 2026-08-26 — Comparativa histórica completa (cierre de Phase 2)
- Commit `165af5d`: implementación exacta del diseño aprobado, sin desviaciones.
  - `main.py`: `GET /api/pipelines/compare?target_id=N` — query literal del diseño (`SELECT id, mode, score, findings, started_at, finished_at FROM pipelines WHERE target_id = ? ORDER BY started_at ASC`); devuelve `target_id/target_name/target_host` + runs con `findings_count` (parseado del JSON, 0 si NULL/corrupto) y `score` parseado (NULL legacy = null, el frontend pinta n/a). 404 si el target no existe. El blob crudo de findings NO viaja al cliente.
  - `index.html`: vista de evolución (`showTargetEvolution`) — tabla cronológica antigua a reciente (# / run / modo / fecha / findings / score) + sparkline en `<canvas>` puro (escala fija 0-100, rejilla 0/25/50/75/100, línea + puntos + labels, dpr-aware, colores de las variables CSS del tema; runs sin score se saltan en la línea). Botón **Evol** en la tabla de pipelines de History y en `viewPipelineResult` (usa `data.target_id`); el nombre del target es clicable. Guía in-app: párrafo "Target evolution" + fila del endpoint en la API Reference.
  - Sidebar: contador "35 tools • 6 categories" hardcodeado sustituido por id `sidebar-toolcount` rellenado desde `/api/tools` al init — cierra el bug cosmético registrado arriba (era 40 tools reales).
  - Tests: `tests/test_compare_endpoint.py`, 3 tests con DB temporal (monkeypatch `models.DB_PATH`, patrón Fase 0.4, sin red): orden cronológico + scores/findings_count parseados con 3 runs del mismo target, 404 target desconocido, filas legacy NULL/JSON corrupto.
- Suite: 146 tests en verde (143 + 3), ruff limpio, compileall OK. Smoke real del endpoint contra DB temporal: ruta registrada sin shadowing y respuesta correcta. Sintaxis JS validada con node.
- Push a origin/master hecho (CI + Railway). Sin dependencias nuevas; MVP intacto.
- Siguiente micro-paso: **Phase 3** — arrancar por 3E (CLI headless, dark mode persistente, búsqueda en History) o, si el usuario prefiere, el micro-paso opcional 3b (delta new/fixed/persistent por `finding_id` entre runs adyacentes, bonus del diseño de comparativa). Decisión al arrancar la sesión.

### 2026-08-26 — Phase 3: decisión de ruta — micro-paso 3b PRIMERO, luego 3E
- Decisión del usuario: se hace **3b primero** (delta new/fixed/persistent por `finding_id` en la comparativa) para cerrar la comparativa histórica de verdad; después se salta a **3E dividido en sub-micro-pasos**: (1) CLI headless, (2) dark mode persistente, (3) búsqueda en History. Razón: 3b es pequeño (estimación 1-2 h), cierra Phase 2 con un cierre redondo y usa datos que acaban de entrar en producción.
- DISEÑO APROBADO de 3b (implementar directo, sin releer nada más):
  - Backend en `compare_pipelines` (main.py): el parseo de findings ya existe server-side (alimenta `findings_count`); se extrae `finding_id` de cada finding y se comparan runs ADYACENTES en orden cronológico (N vs N-1): `new` = ids de N no en N-1, `fixed` = ids de N-1 no en N, `persistent` = comunes. Primera run: listas vacías. Findings NULL/corrupto legacy = conjunto vacío (coherente con `findings_count=0`).
  - Respuesta: cada run lleva `new`, `fixed`, `persistent`, listas de `{finding_id, severity, title}` (id = identidad; severity+title para mostrar; sin evidence completa para no inflar). Siempre incluidas, SIN flag opcional.
  - Frontend en `showTargetEvolution` (index.html): badges con conteos en la tabla de evolución (p. ej. "+2 new / 1 fixed") + panel desplegable por run listando new/fixed/persistent con title y severity. Sin librerías nuevas.
  - Tests: 2-3 tests con runs sintéticas, DB temporal (monkeypatch `models.DB_PATH`, sin red): delta correcto entre dos runs consecutivas; primera run con delta vacío; findings NULL legacy = conjunto vacío sin romper.
  - Leer ANTES de tocar nada: `finding_id` en `backend/findings.py` (identidad estable — verificar cómo se genera para asegurar que el mismo finding comparte id entre runs), `compare_pipelines` en main.py, y la tabla/función de evolución en index.html.
- Commit `feat:`, suite verde antes de push. Al cerrar sesión: actualizar registro + footer con el siguiente micro-paso.
- Siguiente micro-paso: implementar 3b según este diseño. Al cerrarlo, arrancar 3E sub-micro-paso 1 (CLI headless).

### 2026-08-26 — Micro-paso 3b completa (delta new/fixed/persistent en la comparativa)
- Commit `1376001`: implementación del diseño aprobado, sin desviaciones.
  - `findings.py`: **`finding_id` ahora es determinista** — sha1 de `tool|category|severity|title` (12 hex) calculado en `__post_init__`, en vez de `uuid4().hex[:12]` aleatorio (que rompía la identidad entre runs; era la advertencia clave del diseño). Los adapters pueden seguir pasando un `finding_id` explícito si conocen mejor key. Verificado: ningún otro módulo dependía del id anterior.
  - `main.py compare_pipelines`: cada run lleva `new`/`fixed`/`persistent` (listas de `{finding_id, severity, title}`, sin evidence) comparando **N vs N-1 cronológico**; primera run = listas vacías; findings NULL/corrupto legacy = conjunto vacío. Siempre incluidas, sin flag.
  - `index.html showTargetEvolution`: columna "Delta vs anterior" con badge de conteos (`+N new / M fixed / K persistent`, primera run = "baseline") y panel desplegable por run listando new/fixed/persistent con severity (tag red/yellow existente) y title. Sin librerías nuevas. Guía in-app actualizada.
  - Tests: 2 nuevos en `test_compare_endpoint.py` (delta correcto entre 3 runs consecutivas con primera vacía; NULL/corrupto = conjunto vacío sin romper) + 1 en `test_findings.py` (id estable entre instancias, cambia con title/severity, explícito respetado). Suite **149** en verde, ruff limpio, compileall OK, sintaxis JS validada con node.
- Nota de transición: los pipelines persistidos antes de este commit tienen ids aleatorios; la primera comparación real tras desplegar mostrará todo como `new` una única vez (los ids nuevos son deterministas desde ya).
- Siguiente micro-paso: **3E sub-micro-paso 1 — CLI headless**.

### 2026-08-26 — 3E sub-micro-paso 1 completa (CLI headless)
- Commit `feat:` en `backend/cli.py` + `tests/test_cli.py`. Entry point: `python -m backend.cli --target HOST [--pipeline {deep,fast,full_depth,nuclear}] [--json]`.
- **Decisión de alcance**: sin `--save`/persistencia — un run CLI no tiene identidad web (¿qué target_id? ¿aparece en History?); persistirlo es una decisión de diseño propia que se deja fuera. Sin `--timeout` (el runner no tiene hook; los timeouts son por-tool dentro de `run_tool`) y sin `--output` (la redirección de shell cubre el caso). CLI = headless puro: sin DB, sin web.
- `PipelineRunner(pipeline_id=0, mode=..., target=..., on_progress=None)` + `await runner.run()`; validación previa con `validators.validate_target` (en modo local ya permite IPs privadas, no hace falta variante). Salida texto: resumen (mode/target/status/elapsed/tools/findings/score + fases con conteo ok). Salida `--json`: el dict completo del runner. Exit codes: 0 ok, 1 target inválido o pipeline fallido, 2 args inválidos (argparse), 130 Ctrl+C.
- Tests: 7 nuevos en `test_cli.py` (JSON parseable e idéntico al resultado, resumen texto con fases, modo/target pasados al runner, `--pipeline` inválido → SystemExit 2, target ausente → SystemExit 2, target vacío → exit 1 stderr "invalid target", pipeline fallido → exit 1). Stub de `PipelineRunner.run`, sin red. Suite **156** en verde (149 + 7), ruff limpio, compileall OK.
- Siguiente micro-paso: **3E sub-micro-paso 2 — dark mode persistente** (y luego 3: búsqueda en History).

### 2026-08-26 — 3E sub-micro-paso 3 completa (búsqueda en History) + decisión sobre el 2
- Commit `85f51f3`. Reordenación aprobada por el usuario: se salta el sub-micro-paso 2 y se hace primero el 3.
- **Decisión de alcance del 2 (dark mode)**: la app es dark POR DEFECTO — todo el CSS está construido sobre `--bg-primary: #0d1117` y textos claros. Por tanto "dark mode persistente" no es cablear un toggle: es implementar un MODO CLARO alternativo conmutable. Eso requiere definir paleta light (`--bg-primary/secondary/card`, `--border`, `--text-*`, `--accent`) y revisitar sombras, gradientes y badges inline (rgba fijos) que rompen en light. Queda como **backlog**: refactor de CSS con variables duales (`[data-theme="light"]`) + toggle + localStorage, en una sesión dedicada.
- **Implementación del 3** (nota: ya existía búsqueda de TEXTO client-side por mode/target/host/status; el incremento real son los filtros exactos server-side):
  - `main.py GET /api/pipelines/history`: query params opcionales `mode` (exacto), `status` (exacto) y `q` (LIKE case-insensitive sobre mode + target name + host). Sin params = comportamiento anterior. WHERE construido con placeholders parametrizados; ORDER BY started_at DESC LIMIT 20 intacto.
  - `index.html renderHistoryPage`: en la pestaña Pipelines, dos selects (modo: fast/deep/full_depth/nuclear; status: completed/running/failed/cancelled) que pasan los query params vía URLSearchParams; state `historyPMode`/`historyPStatus`. El filtro de texto client-side se conserva como fallback.
  - Tests: 3 nuevos en `tests/test_pipelines_history.py` (sin filtros = todo en DESC + join target presente; mode/status exactos y combinados sin match = vacío; q sobre host/mode/nombre con case-insensitive). DB temporal con monkeypatch `models.DB_PATH`, sin red.
- Suite **159** en verde (156 + 3), ruff limpio, compileall OK. master == origin/master.

### 2026-08-26 — 3E sub-micro-paso 2 completa (modo light dedicado) — CIERRE DE 3E
- Commit `6f230b0` (solo `frontend/index.html`, +41 líneas). El usuario eligió la dirección A: UI pulida antes que hardware.
- **Paso 0 de auditoría** (decisión previa): el diseño ya estaba 100% variable-driven — 179 usos de `var(--...)`, todos los gradientes (shimmer/progress/skeleton) con variables, 0 inline styles con colores literales, solo 4 hex fuera de `:root` (`.btn-primary`/`.btn-danger`, válidos en light). Sin refactor necesario.
- **Implementación**: bloque `[data-theme="light"]` con paleta estilo GitHub-light (`--bg-primary #f6f8fa`, `--bg-secondary/card #ffffff`, `--border #d0d7de`, `--text-primary #1f2328`, `--accent #0969da`, semánticas oscurecidas, sombras suaves). Toggle «Tema:» en sidebar-header → `toggleTheme()` definido en script inline de `<head>` (apply antes del paint = sin FOUC) + persistencia `localStorage['sd-theme']`; label dinámico.
- **Registrado**: 36 tints `rgba(canales fijos, alpha bajo)` — funcionan en ambos temas por ser translúcidos; el JS de charts lee las CSS vars en runtime (se repintan al re-render). Backlog opcional: variables duales para los rgba si algún tint queda pálido en light.
- Verificación: suite **159** en verde, ruff limpio, compileall OK. master == origin/master @ `6f230b0`. **3E CERRADA** (pasos 1, 2 y 3).
- Siguiente micro-paso: definir con el usuario — candidates: B WiFi Marauder v6 / CYD Marauder (reutiliza `wifi.py`, viewers ya exponen JSON, 1-2 h), C Bruce RF/BLE (nuevo `backend/tools/bruce.py`, requiere capturas reales de serial/formato), D HackRF / Bus Pirate (parsers `.c16` + I2C/SPI/UART, requiere capturas reales obligatorias).

### 2026-08-26 — CLI enrichment completa (--tool individual + --list-tools + --list-pipelines)
- Commit `8ef2853` (`backend/cli.py` + `tests/test_cli.py`, +249/-24). Decisión del usuario: enriquecer la CLI para dar libertad real a los servicios, sin abrir persistencia CLI (`--save`) ni hardware.
- **`--tool TOOL_ID --target HOST`**: ejecuta `scanner.run_tool(tool_id, target)` directamente (no pipeline). Valida tool_id contra `scanner.HANDLERS` (desconocido → exit 2, "unknown tool"). Para tools especiales (hash_checker, password_audit, cve_search, system) el target es la entrada cruda, igual que en web; solo los pipelines validan host (`validate_target`). Salida: resumen texto (tool/target/status/elapsed/findings/score) o JSON con `--json`; fallo → exit 1 + error en stderr (JSON si `--json`).
- **`--list-tools`**: tabla ID | NAME | CATEGORY | DESCRIPTION desde `config.TOOLS`, ordenada por categoría (orden del registro `CATEGORIES`) y luego nombre.
- **`--list-pipelines`**: una fila por fase: MODE | PHASE | TOOLS.
- **Mutua exclusión**: `--tool` + `--pipeline` → `parser.error` exit 2. Las acciones list son informativas, toman precedencia sobre el resto y no piden `--target`. Contratos previos intactos: target ausente en pipeline → exit 2; target solo espacios → `validate_target` exit 1.
- **Backlog (sin tocar)**: `--save`/persistencia CLI (decisión de diseño propia: identidad del run en History), TUI (rich/curses), hardware B/C/D (C/D requieren capturas reales).
- Tests: 11 nuevos con stubs de `scanner.run_tool` (incluido stub que lanza AssertionError si se ejecuta en acciones list); suite **170** en verde, ruff limpio, compileall OK.
- Siguiente micro-paso: definir con el usuario — hardware B (WiFi Marauder v6 / CYD Marauder, reutiliza `wifi.py`, 1-2 h) u otra cosa del plan; la CLI de libertad queda cerrada.

### 2026-08-26 — Badge tools-count dinámico + cola de micro-pasos fijada por el usuario
- Commit `c728d3d` (solo `frontend/index.html`, +3/-1): el badge `#tools-count` de la nav Tools se actualiza en el boot desde `/api/tools` dentro de `updateSidebarToolCount()` — mismo fetch que el contador del sidebar, una sola fuente de verdad. El 35 estático era obsoleto (el registro `TOOLS` tiene 40) y solo se corregía al visitar la pestaña Tools; fallback HTML a 40.
- **Cola de micro-pasos fijada por el usuario** (antes de hardware/TUI; ordenado por impacto/coste, cero parsers binarios):
  1. **Rate limiting** en /api/scans, /api/pipelines, /api/targets — middleware por IP/API key (p. ej. 30 req/min), diccionario en memoria sin Redis. Impacto: seguridad inmediata (app expuesta en Railway).
  2. **Paginación server-side** en History — page/per_page en /api/pipelines/history y /api/scans (hoy el frontend pagina con offset/limit a su criterio). Impacto: escalabilidad.
  3. **F1-FAVICON** — hash MD5/SHA256 de /favicon.ico + paths comunes, lookup contra base de hashes de stacks; alimenta tech_detector/cve_correlation. Recon pasivo puro; cierra Fase 1 técnicamente.
  4. **Export CSV** — /api/pipelines/{id}/export/csv y/o /api/scans/{id}/export/csv (csv stdlib). Formato que consumen SIEMs y hojas de cálculo.
  5. **Logging estructurado** — logging con niveles + archivo rotativo en vez de print(); diagnóstico real en producción.
  - Candidatos pendientes fuera del orden estricto: tests de integración end-to-end (httpx.AsyncClient(app=main.app) + DB temporal), variables de entorno para config (PORT, API_KEY, DB_PATH, REMOTE_MODE, SPLUNK_*).
  - Tras la cola: hardware/TUI cuando haya capturas reales.

### Backlog de integraciones OSINT / threat intel (fuentes del PDF de kinomakino)
Prioridad para ampliar recon pasivo y threat intel sin hardware ni parsers binarios. Todas siguen el patron existente: handler async → adapter en `findings.py` → registro en `TOOLS`/`HANDLERS` → tests sin red.

| # | Tool | Modulo | Fuente | API key | Estimacion | Notas |
|---|---|---|---|---|---|---|
| 1 | `wayback_urls` | `web.py` | archive.org | No | 1-2 h | URLs historicas de un dominio. Alto impacto para recon; encuentra endpoints muertos. |
| 2 | `exploitdb_search` | `vuln.py` | exploit-db.com | No | 1-2 h | Exploits publicos por producto/CVE. Complementa F1-CVE. |
| 3 | `shodan_lookup` | `osint.py` | shodan.io | Si | 2-3 h | Puertos, banners, CVEs, tags. Requiere API key configurable via env/UI. |
| 4 | `dnsdumpster_enum` | `network.py` | dnsdumpster.com | No | 1-2 h | Subdominios + DNS. Scraping sencillo. Complementa `subdomain_enum`. |
| 5 | `publicwww_search` | `osint.py` | publicwww.com | Si (free tier) | 2 h | Codigo expuesto por dominio. Complementa F1-SECRETS. |

Alternativas del mismo nivel si alguna de las anteriores no encaja:
- `searchcode_search` (searchcode.com): codigo en repositorios publicos.
- `grepapp_search` (grep.app): busqueda en Git.
- `vulners_search` (vulners.com): vulnerabilidades + exploits, alternativa/complemento a ExploitDB.
- `otx_lookup` (otx.alienvault.com): threat intel por IP/dominio/hash.
- `greynoise_lookup` (greynoise.io): clasificacion de IPs escaneando internet (ruido vs amenaza real).
- `urlscan_submit` / `urlscan_lookup` (urlscan.io): analisis de URL.
- `securitytrails_enum` (securitytrails.com): DNS historico y subdominios.
- `hunter_email_finder` (hunter.io): emails de un dominio.

Fuera de alcance por ahora (pagadas o complejas):
- Dehashed (pagada).
- WiGLE (requiere contexto/hardware WiFi).
- Polyswarm (malware, complejo).
- Pastebin (API dificultosa, mucho ruido).

Reglas para cada tool de este backlog:
1. Sin dependencias nuevas si es posible (`httpx`/`aiohttp` ya estan; `bs4` solo si el scraping lo justifica).
2. Las API keys deben ser configurables via environment o UI (Settings > API Keys), nunca hardcodeadas.
3. Tests con stubs/monkeypatch, sin red.
4. Adapter `@register("tool_id")` en `findings.py` desde el dia uno.
5. Timeout y manejo de errores best-effort: si la API externa falla, el scan devuelve lo que tenga sin romper.

- Siguiente micro-paso: **rate limiting**.

### 2026-08-26 — Rate limiting completo (cola de micro-pasos, paso 1)
- Commits `6df6c70` (feat) + docs de cierre. `backend/ratelimit.py` NUEVO: `RateLimiter` sliding-window en memoria (deque por clave; los rechazos NO se registran y no alargan la prohibición; GC a 4096 claves para acotar memoria; reloj inyectable). Cableado en `main.py`: bucket estricto **30 req/min por IP** en POST /api/scans|pipelines|targets (rutas exactas), bucket de lectura **600 req/min por IP** en GET /api/* (la UI hace polling cada ~2s durante un run), respuesta **429 con `Retry-After`** (segundos hasta que expira el hit más viejo, mín. 1).
- Decisiones: (1) clave = direct peer SOLO — XFF NO confiable (header spoofeable = el atacante se acuña buckets frescos rotando el valor); detrás de CF la granularidad degrada a per-origin, aceptado en MVP porque sigue acotando la tasa total de mutación del deploy. (2) El middleware se define tras `require_api_key` → es el más externo → corre PRIMERO: los floods se limitan antes que el auth. (3) Alcance: solo las 3 rutas POST exactas; otras mutaciones (cancel, delete, webhooks, splunk, reset) NO limitadas en el MVP — registrado como extensión posible. (4) Límite de lectura 600 = margen amplio para polling legítimo, flood guard.
- Tests: 9 nuevos en `tests/test_ratelimit.py` (reloj congelado SIN monkeypatch de time.monotonic; middleware probado directamente con Request de starlette fabricados + call_next stub, sin red): límite+rechazo, expiración sliding por hit, rechazos no alargan, retry_after = expiración del más viejo, claves independientes, GC, mapeo/limites de buckets, 429+Retry-After+sin call_next al rechazar, passthrough ilimitado. Suite **179** en verde (170 + 9), ruff limpio, compileall OK.
- Smoke in-proceso (ASGI crudo, sin httpx): GET /api/status → 200; 30 POST /api/scans con body inválido → 422 de validación (el rate limit deja pasar hasta routing); el 31 → **429 Retry-After: 60**.
- Siguiente micro-paso: **paginación server-side** (page/per_page en /api/pipelines/history y /api/scans).

### 2026-08-26 — Paginación server-side completa (cola de micro-pasos, paso 2)
- Commit `e528101`. Backend: `/api/scans` pasa de offset/limit a **page/per_page** (1-based; per_page default 50 = el límite anterior) y `/api/pipelines/history` GANA paginación (antes `LIMIT 20` duro, sin params). Respuesta de ambos: `total`/`page`/`per_page` además de `scans`/`pipelines`; per_page cap **200**, page<1 clamp a 1; el COUNT usa la MISMA WHERE que el fetch (los filtros mode/status/q y target_id cuentan bien). Decisione registrada: offset/limit se retiran (breaking; los únicos consumidores eran el frontend de este repo + la tabla guía, actualizada).
- Frontend (`frontend/index.html`): state `historyPage`/`historyPPage` sustituyen a `historyOffset`/`historyLimit`; scans per_page=50, pipelines per_page=20; las tabs muestran el **total server-side** (antes: filas de la página); Prev/Next en AMBOS tabs (el de pipelines no existía y estaba recortado a 20); "Showing X of Y (page N)". `viewScanResult` ahora usa `GET /api/scans/{id}` en vez de escanear la primera página de `/scans` (bug latente: ids fuera del top-50 no se encontraban).
- Tests: 7 nuevos — `tests/test_scans_pagination.py` NUEVO (4: envelope+orden DESC, slicing sin huecos ni solapes p1+p2+p3 == lista completa, total con filtro target_id, clamping page/per_page) + 3 en `test_pipelines_history.py` (envelope+slicing+página vacía al final, filtros x paginación, clamping). Suite **186** en verde (179 + 7), ruff limpio, compileall OK.
- Smoke in-proceso (ASGI crudo, sin httpx): `/api/scans?page=2&per_page=2` → 200 con 2 filas de total 5 (offset 2); `/api/pipelines/history?page=1&per_page=5` → 200.
- Siguiente micro-paso: **F1-FAVICON** (hash MD5/SHA256 de /favicon.ico + paths comunes, lookup por hash contra stacks; cierra Fase 1).

### 2026-08-27 — F1-FAVICON completo (cierra Fase 1)
- Commit `912676b`. Tool `favicon_fingerprint` NUEVO en `backend/tools/favicon.py`: GET pasivo de `/favicon.ico`, `/favicon.png`, `/icon.png`, `/apple-touch-icon.png`; MD5 + SHA256 por icono; lookup contra la base local `data/favicon_hashes.json` (NUEVA: 6 favicons OFICIALES REALES fetch-eados 2026-08-27 — WordPress, Drupal, Joomla, Shopify, Ghost, Wix; Squarespace/Webflow bloquearon el fetch y quedaron fuera). Resultado: `target` (origen normalizado), `icons` (path/content_type/bytes/md5/sha256), `matches`, `stack` (primera coincidencia o None).
- Decisiones registradas: (1) match = senal INFO de instalacion por defecto / sin rebrandear, no vulnerabilidad; sin iconos = sin finding. (2) El tool NO entra en pipelines (no toca full_depth/nuclear): es standalone (Tools/CLI), alimenta el reporte via findings — meterlo en fases queda como extension. (3) Renderer PDF: fallback JSON generico de `report.py` (sin renderer dedicado, MVP). (4) Base extensible editando `data/favicon_hashes.json` (formato: name/source/content_type/bytes/md5/sha256).
- Cableado: entrada en `TOOLS` (Web Security, icon Fv, timeout 30), `HANDLERS` scanner, adapter `@register("favicon_fingerprint")` en findings.py (match = INFO con hash+source; icono desconocido = INFO con md5/sha256 para lookup manual). Badge tools-count y lista CLI/Tools son dinamicos: 40 -> 41 sin tocar frontend.
- Tests: 8 nuevos en `tests/test_tools_favicon.py` (integridad de la base real sin red, match/unknown/sin-iconos con fetch stubeado estilo secret_leak_scan, fallo de fetch, adapter x3). Suite **194** en verde (186 + 8), ruff limpio, compileall OK.
- Smoke in-proceso (red real, manual): `run_tool("favicon_fingerprint", "wordpress.org")` → stack WordPress, match /favicon.ico 4286B, finding INFO, score 0 (INFO no puntua).
- Siguiente micro-paso: **export CSV** (/api/pipelines/{id}/export/csv y/o /api/scans/{id}/export/csv, csv stdlib).

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

*Última actualización: 2026-08-26, Phase 2 CERRADA de verdad — Full Depth (`a0cf16a`) + executive PDF (`10ed28f`) + comparativa histórica con delta new/fixed/persistent (`165af5d` + `1376001`); **3E CERRADA**: sub-micro-pasos 1 CLI headless (`3da329e`), 2 modo light dedicado (`6f230b0`) y 3 búsqueda en History (`85f51f3`) completos; **CLI enrichment completa** (`8ef2853`): `--tool` individual + `--list-tools` + `--list-pipelines`; badge tools-count dinámico (`c728d3d`); **cola de micro-pasos**: rate limiting COMPLETO (`6df6c70`, 30 req/min/IP mutación + 600 GET, 429+Retry-After) y **paginación server-side COMPLETA** (`e528101`, page/per_page + total en /api/scans y /api/pipelines/history); **F1-FAVICON COMPLETO** (`912676b`, tool favicon_fingerprint + base local de 6 hashes oficiales reales; cierra Fase 1), siguiente export CSV; suite 194 tests en verde; ruff limpio. `912676b` local, push pendiente.

**PROMPT PARA LA PRÓXIMA SESIÓN** (arrancar con contexto nuevo):
Eres el agente de sec-dashboard. Primero lee este archivo entero (la sección 7 son reglas NO VIOLAR). Estado: Fase 1 completa salvo F1-FAVICON (backlog opcional); **Fase 2 COMPLETA**: Full Depth pipeline (`a0cf16a`), executive PDF (`10ed28f`), comparativa histórica con delta new/fixed/persistent por `finding_id` determinista (`165af5d` + `1376001`, endpoint `GET /api/pipelines/compare?target_id=N` con runs que llevan `new`/`fixed`/`persistent` como listas de `{finding_id, severity, title}`; frontend: columna "Delta vs anterior" + panel desplegable en `showTargetEvolution`). **3E**: sub-micro-paso 1 hecho — CLI headless `python -m backend.cli --target ... [--pipeline ...] [--json]` (sin persistencia, decisión registrada); sub-micro-paso 3 hecho — `GET /api/pipelines/history?mode=&status=&q= (ahora también page/per_page) + selects en la pestaña Pipelines de History. Suite 186 tests en verde, ruff limpio.
**CLI enrichment hecha** (`8ef2853`): `python -m backend.cli --tool dns_recon --target example.com [--json]` (run_tool directo; tools especiales toman target como entrada cruda), `--list-tools` (tabla por categoría+nombre) y `--list-pipelines` (fila por fase). Mutua exclusión `--tool`/`--pipeline` (exit 2); acciones list sin target y con precedencia. Pendientes en backlog: `--save`/persistencia CLI, TUI, hardware B/C/D.
**Rate limiting HECHO** (`6df6c70`): `backend/ratelimit.py` (`RateLimiter` sliding-window, rechazos no se registran, GC a 4096 claves) + middleware en main.py — 30 req/min/IP en POST /api/scans|pipelines|targets (rutas exactas), 600 GET /api/*, 429 + Retry-After; clave = direct peer (XFF NO confiable: header spoofeable); corre antes que el auth.
**Paginación server-side HECHA** (`e528101`): page/per_page (1-based) en `/api/scans` y `/api/pipelines/history` con `total`/`page`/`per_page` en la respuesta; per_page cap 200, default 50 (scans) / 20 (pipelines, el antiguo hard cap); offset/limit retirados (breaking registrado, únicos consumidores eran frontend+guía del repo); frontend a página con totals server-side y Prev/Next en ambos tabs; `viewScanResult` a `GET /api/scans/{id}`.
**F1-FAVICON HECHO** (`912676b`, cierra Fase 1): tool `favicon_fingerprint` (modulo propio `backend/tools/favicon.py`) — GET pasivo de 4 paths de icono, MD5/SHA256, lookup contra `data/favicon_hashes.json` (6 favicons oficiales REALES: WordPress, Drupal, Joomla, Shopify, Ghost, Wix); findings INFO; no entra en pipelines (extension registrada); renderer PDF por fallback JSON; base extensible editando el JSON. Suite 194.
Tarea: **seguir la cola fijada por el usuario (2026-08-26), arrancar por export CSV** (`912676b` local, push pendiente de confirmación). Orden restante: 1) export CSV (/api/pipelines/{id}/export/csv y/o /api/scans/{id}/export/csv, csv stdlib); 2) logging estructurado (niveles + archivo rotativo, sin print). **En cola tras estos dos** (idea del usuario, seccion 'Backlog de integraciones OSINT / threat intel' de este mismo archivo): wayback_urls, exploitdb_search, shodan_lookup, dnsdumpster_enum, publicwww_search (+ alternativas y reglas fijadas: keys por env/UI, tests sin red, adapter desde el dia uno, best-effort). Candidatos fuera del orden estricto: tests de integración end-to-end (httpx.AsyncClient(app=main.app) + DB temporal), config por variables de entorno (PORT, API_KEY, DB_PATH, REMOTE_MODE, SPLUNK_*). Tras la cola: hardware/TUI con capturas reales — B WiFi Marauder v6 / CYD (reutiliza `wifi.py`, 1-2 h); C Bruce RF/BLE (`bruce.py` nuevo, REQUIERE capturas reales del serial/formato); D HackRF / Bus Pirate (parsers `.c16` e I2C/SPI/UART, capturas obligatorias). Si se elige hardware C/D: pedir las capturas ANTES de escribir parsers.
Backlog pendiente: variables duales para los 36 rgba fijos si algún tint queda pálido en light; TUI (rich/curses) y `--save` CLI deliberadamente fuera hasta tener motivo. F1-FAVICON ya está dentro de la cola (paso 3). NUEVO backlog registrado: integraciones OSINT/threat intel desde el PDF de kinomakino — `wayback_urls`, `exploitdb_search`, `shodan_lookup`, `dnsdumpster_enum`, `publicwww_search` y alternativas (`searchcode`, `grep.app`, `vulners`, `otx`, `greynoise`, `urlscan`, `securitytrails`, `hunter.io`).
Reglas: MVP sin dependencias nuevas, tests sin red, commits `feat:`/`fix:`, push solo con suite verde, sin emojis.
Al cerrar sesión: actualizar las tablas/sección 6 de este archivo y el footer con el siguiente micro-paso.
