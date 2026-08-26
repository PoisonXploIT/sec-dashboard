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
- **Último commit**: `788bde5` — "test: Fase 0 — pytest suite (49 tests), unified Finding model, CI (ruff+pytest)"
- **Fecha del commit**: 2026-08 (sesión de Fase 0).
- **Estado del plan**: Fase 0 en curso — hechas tareas 0.1 (tests), 0.3 (modelo Finding) y 0.2 (CI). Pendiente tarea 0.4 (refactor salidas: findings[] en el pipeline de ejecución).

### Comandos de referencia (siempre desde el repo)

```powershell
# Activar venv (ya tiene dependencias + pytest + ruff instalados)
.venv\Scripts\python.exe -m pytest -q          # suite completa (49 tests, ~0.6s, sin red)
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
| 0.4 | Refactor salidas: tools devuelven findings[] además del JSON legible, sin romper UI | PENDIENTE |

### Fase 1 — Tools de profundidad (diferenciador)
Prioridad: **Tech CVE Correlation** y **Subdomain Takeover** primero.
- Subdomain Takeover: cruza CT logs + CNAMEs, detecta dangling NXDOMAIN hacia GitHub Pages, Heroku, S3.
- Tech CVE Correlation: toma output de `tech_detector`, identifica versión, cruza contra NVD/CISA KEV.
- Secret Leak Scanner: `.git/` expuesto, API keys, tokens en JS/robots.txt (regexs tipo TruffleHog).
- SSL Deep Analyzer: grade A+–F (cipher suites, TLS 1.0/1.1, HSTS, OCSP stapling).
- DNS Zone Hygiene: SPF permisivo (+all), DKIM selector brute, DMARC p=none, DNSKEY débil.
- Favicon/Stack Fingerprinting: hashes de favicons + paths estáticos para versiones exactas.

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

## 5. SIGUIENTE PASO — Fase 0.4 (refactor salidas con findings)

### Objetivo
Enganchar `extract_findings()` en el flujo de ejecución y persistir `findings[]` junto al resultado actual, SIN cambiar la UI (sigue renderizando el JSON normal; findings viaja por API/DB).

### Cambios mínimos (ya localizados en el código)

1. **Schema DB** (`backend/models.py` `SCHEMA`):
   - Añadir columna `findings TEXT` a `scans` y `pipelines` (default `[]`).
   - Añadir migration automática en el `startup` de `backend/main.py` (patrón existente: líneas ~300-330, recrear tabla con `RENAME TO scans_old` si la columna no existe — el patrón de `target_id` nullable ya está hecho ahí).

2. **scanner.run_tool** (`backend/scanner.py`):
   - Después de obtener `result` del handler: `findings = extract_findings(tool_name, result, target)`.
   - Añadir `findings` al dict de retorno (junto a `success`, `elapsed_seconds`, `result`).

3. **Persistencia** (`backend/main.py`):
   - `create_scan` / `_run_scan` (líneas 558-673): INSERT en 590, UPDATE en 621 — incluir findings serializados.
   - `create_pipeline` / loop de fases (líneas 757-830): UPDATE en 790 — agregar findings del pipeline.
   - `backend/pipeline.py` línea 106: `run_tool` interno — recoger findings de cada tool.
   - OJO: los endpoints de export (`export_scan_json` en 144, etc.) y `report.py` pueden ignorar findings por ahora (compatibilidad).

4. **Backward compatibility**: el fallback de `extract_findings` ya devuelve [] o INFO — no rompe nada. La UI no consume findings todavía.

### Decisiones pendientes (recomendación del usuario)

- **¿Score se guarda en DB o se calcula on-the-fly?** → RECOMENDADO: guardarlo (`score INTEGER` en scans/pipelines) para poder ordenar/buscar por score en History.
- **¿Findings del pipeline agregados o por tool?** → RECOMENDADO: AMBOS — cada scan interno guarda sus findings, y el pipeline guarda un findings agregado + score total.

### Tests nuevos para 0.4
- Scan de tool con adapter → DB contiene findings no vacío.
- Scan de tool sin adapter → findings == [].
- Pipeline → findings agregados por fase (o por tool; decidir).
- `score_findings()` computado y guardado en el scan.

### Orden recomendado
1. Push del commit actual (ya confirmado por el usuario) y ver CI en verde en GitHub.
2. Implementar Fase 0.4 en commit nuevo.
3. Con 0.4 verde, Fase 1 (tools de profundidad) puede usar el modelo de findings desde el día uno.

---

## 6. Reglas y restricciones del proyecto (NO VIOLAR)

1. **NO emojis, flechas de texto ni símbolos de color** en ninguna salida, nota, script o commit (regla global del usuario). Escribir las palabras.
2. **Local-first**: priorizar herramientas/skills locales; el modelo se queda local; solo APIs externas como fuentes de datos (NVD, CISA KEV, HIBP, MalwareBazaar, etc.).
3. **M1**: los tracebacks se logean server-side, NUNCA al cliente (ya cubierto por tests).
4. **Solo recon/pasivo**: nada de explotación activa ni jamming (legal).
5. **Hardware**: puedo escribir todo el software (viewers, polling, importes, watchers de carpeta, sourcetypes), pero los parsers de serial/formatos (Bruce serial, .sub/.nfc/.ir, .c16) necesitan **capturas reales del usuario** para validarse.
6. **Sin multiusuario/roles** (fuera de alcance deliberado).
7. Los tests NUNCA deben depender de red; usar stubs/monkeypatch.
8. Push a origin/master dispara CI y, vía Railway, deploy a sec.sammideblas.com — confirmar con el usuario antes de push cuando haya dudas (esta vez ya está confirmado).

---

## 7. Referencias

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

*Última actualización: sesión Fase 0 (commit 788bde5). Próxima sesión: leer este archivo, verificar estado de CI en GitHub, implementar Fase 0.4.*
