# sec-dashboard — Auditoría de bugs (2026-08-17)

Método: revisión estática de los 8.113 LOC + pruebas en vivo contra la app
(local en 127.0.0.1:8444 y una segunda instancia con `SEC_DASHBOARD_REMOTE=1`
en 8445 simulando el deploy de Railway). Todos los hallazgos marcados como
**VERIFICADO** fueron reproducidos en vivo.

## Resumen

| Severidad | Nº | Estado |
|---|---|---|
| 🔴 Critical | 2 | 2 verificados en vivo |
| 🟡 Medium | 4 | 3 verificados, 1 estático |
| 🔵 Low | 4 | 1 verificado, 3 estáticos |

---

## 🔴 CRITICAL

### C1 — Bypass total del SSRF en `/api/tools/{tool_id}/run` (remote mode) ✅ FIXED
**Fix aplicado 2026-08-17 y verificado:** `run_single_tool` ahora llama
`validate_target()` para todas las tools de red/web/OSINT (excluye special,
system y wifi que ya validan). Verificado en instancia remote: IP privada,
loopback y URL con metadata devuelven 400; `8.8.8.8` y tools de sistema
siguen funcionando.

**VERIFICADO EN VIVO (hallazgo original).**

`create_target` y los webhooks validan con `validate_target()`, pero
`run_single_tool` (main.py:432-440) acepta `body.target` crudo y se lo pasa
directo a `run_tool()`. Con la app en modo remoto:

```
POST /api/tools/port_scanner/run {"target":"192.168.1.1"} → 200 OK, escanea la LAN
POST /api/tools/port_scanner/run {"target":"127.0.0.1"}    → 200 OK, escanea el propio server
POST /api/tools/http_probe/run  {"target":"http://169.254.169.254/..."} → intento de fetch
```

En el deploy público (sec.sammideblas.com en Railway), cualquiera puede usar
el servidor como proxy de escaneo contra la red interna del contenedor,
metadata endpoints de cloud, etc. Afecta a las ~30 herramientas con target.

**Plan de ejecución:**
1. En `run_single_tool`, tras resolver `effective_target`, llamar
   `validate_target(effective_target)` cuando NO sea special tool ni system
   tool; si falla → `HTTPException(400, reason)`.
2. Ojo: las system tools ignoran target, y las wifi tools ya tienen su propia
   validación (`_validate_viewer_url`) — excluirlas para no romperlas.
3. Añadir el mismo check en `create_scan` por si `target_id` apunta a un
   target creado antes del fix (defensa en profundidad).
4. Test de regresión: repetir los 3 curls de arriba en instancia con
   `SEC_DASHBOARD_REMOTE=1` y exigir 400.

### C2 — API pública sin autenticación en el deploy remoto ✅ FIXED
**Fix aplicado 2026-08-17 y verificado:** middleware `require_api_key` —
si `SEC_DASHBOARD_API_KEY` está definida, todo `/api/*` exige header
`X-API-Key` (401 si falta/es incorrecta) y el WebSocket `/ws` exige
`?key=` (403 sin ella). Sin la env var, comportamiento local sin cambios.
El frontend guarda la key en localStorage y la pide con un prompt al
recibir 401. `GET /` sigue público. **Pendiente:** definir
`SEC_DASHBOARD_API_KEY` en las env vars de Railway.

**Verificado (diseño + prueba en vivo) — hallazgo original.**

No existe auth en ningún endpoint. En local es aceptable (127.0.0.1), pero el
mismo código corre en Railway con URL pública. Cualquiera puede:
- Ejecutar `system_info`, `network_connections`, `process_monitor`
  (verificado: devuelve OS, hostname, IPs, procesos del servidor).
- Lanzar `ps_security_audit` (PowerShell con ExecutionPolicy Bypass).
- `DELETE /api/reset?confirm=true` — borrado total de datos.
- Cambiar config de proxy/Splunk (`POST /api/proxy`, `POST /api/splunk`).
- Leer TODO el historial y exportarlo (`/api/export/all/json`).

**Plan de ejecución:**
1. Añadir middleware de API key: leer `SEC_DASHBOARD_API_KEY` del entorno;
   si está definida, exigir header `X-API-Key` en todas las rutas `/api/*`
   y `/ws`. Si no está definida → comportamiento actual (local).
2. En Railway, definir la env var. En local, no definirla.
3. Excluir solo `GET /` (frontend) — el JS leerá la key de un campo en la UI
   o de `?key=` almacenado en localStorage.
4. Documentar en README: "remoto sin API key = instancia pública abierta".
5. Alternativa mínima si no quieres auth: en remote mode, deshabilitar
   system tools, ps_security_audit, /api/reset, /api/proxy, /api/splunk y
   exports (whitelist de endpoints read-only).

---

## 🟡 MEDIUM

### M1 — Tracebacks completos en respuestas de error ✅ FIXED
Verificado: el JSON de error ya no incluye `traceback` (se loguea en
consola del server con `traceback.print_exc()`).
**VERIFICADO.** `scanner.py:122` incluye `traceback.format_exc()` en el JSON
que se devuelve al cliente (y se guarda en DB). Filtra rutas absolutas del
servidor, versiones de Python y estructura interna:
```
{"error":"'int' object has no attribute 'isdigit'","traceback":"Traceback...
C:\\Users\\Sammi\\sec-dashboard\\backend\\scanner.py..."}
```
**Plan:** quitar `traceback` del dict devuelto (logearlo solo a consola/fichero).
Cambio de 3 líneas en `scanner.py`. Test: provocar el error y verificar que el
JSON ya no trae la clave.

### M2 — `hash_checker`: MalwareBazaar nunca funciona ✅ FIXED
Verificado: la causa raíz era doble — (1) claves en mayúsculas y (2)
abuse.ch ahora exige Auth-Key gratuita (HTTP 401 sin ella). Fix: claves
minúsculas + header `Auth-Key` desde `MALWAREBAZAAR_API_KEY` + el error
de cada fuente ahora es visible en la respuesta en vez de desaparecer.
**Pendiente:** crear cuenta en bazaar.abuse.ch y definir
`MALWAREBAZAAR_API_KEY` para que la fuente funcione.
**VERIFICADO.** Se probó con el MD5 de EICAR (`44d88612...`, presente
garantizado en MB) y la fuente MalwareBazaar ni aparece en el resultado.
Causa: `vuln.py:118` envía `data = {"query":"get_info", hash_type: hash_value}`
con clave `"MD5"`/`"SHA-1"`/`"SHA-256"`, pero la API exige minúsculas
(`md5`/`sha1`/`sha256`) → `query_status=invalid` → cae al except silencioso.
**Plan:** mapear `{"MD5":"md5","SHA-1":"sha1","SHA-256":"sha256"}` y no
tragar el error: si `query_status` no es `ok`/`hash_not_found`, reflejarlo en
`sources.MalwareBazaar`. Test: repetir el curl de EICAR y exigir `found:true`.

### M3 — `ps_security_audit`: race condition en la carpeta de salida ✅ FIXED
Fix: snapshot de carpetas `Auditoria_*` antes de ejecutar; se lee la
carpeta creada por ESTA ejecución (con fallback a la más reciente), y en
timeout se hace `proc.kill()` para no dejar PowerShell huérfano.
**Estático.** `audit.py:116-130` elige `Auditoria_*` más reciente por mtime.
Si dos auditorías corren en paralelo (o una anterior acaba de terminar),
puedes leer la carpeta de otra ejecución y devolver resultados mezclados.
Además, el timeout es 600s pero el tool config marca `timeout` distinto en
`scanner.run_tool` — el `asyncio.wait_for` externo puede matar el proceso a
mitad dejando PowerShell huérfano.
**Plan:** crear la carpeta de salida con nombre único controlado (pasar
`-OutputFolder` si el script lo soporta, o cwd temporal por ejecución);
al cancelar/timeout, matar el proceso (`proc.kill()`) antes de re-raise.

### M4 — Contraseñas del password_audit persisten en la DB ✅ FIXED
Verificado en vivo: scan de `password_audit` persistido con
`target: "(redacted)"` en DB; webhooks y Splunk reciben también
"(redacted)". El resultado en vivo sigue devolviéndose al llamante.
**Estático + verificado parcialmente.** En `create_scan` (main.py:548-550),
para special tools el `direct_input` (la contraseña auditada) se usa como
`target_name` y queda en el historial (`result` JSON con el input). Cualquier
lector de `/api/scans` ve las contraseñas probadas.
**Plan:** para `password_audit`, no persistir el input: guardar
`target_name="(redacted)"` y saneado del campo `target` en el resultado
guardado (el resultado en vivo puede seguir devolviéndolo).

---

## 🔵 LOW

### L1 — `ping_sweep`/`traceroute` solo funcionan en Windows
**Estático.** `network.py:327` tiene `param = "-n" if True else "-c"` (código
muerto, siempre Windows) y `traceroute` llama a `tracert`. En Linux/Docker
(Railway) ambos fallan con FileNotFoundError.
**Plan:** `platform.system()` → elegir `-n/-c` y `tracert/traceroute`.

### L2 — `/api/status`: campo `uptime` es en realidad la epoch actual
**Verificado** (`"uptime":1786996733.79` — es `time.time()`, no uptime).
Ya existe `uptime_seconds` correcto en `/api/dashboard/stats`.
**Plan:** cambiar a `time.time() - START_TIME` o eliminar el campo.

### L3 — `get_tor_status` bloquea el event loop
**Estático.** `proxy.py:121-135` hace `socket.connect_ex` con timeout 3s
síncrono dentro del endpoint async `/api/proxy` — hasta 9s de bloqueo (3
puertos × 3s) si hay filtrado de paquetes.
**Plan:** envolver en `asyncio.to_thread(...)` o reducir timeout a 0.5s.

### L4 — `delete_target`/`delete_scan`/`delete_pipeline` devuelven `{"deleted": true}` aunque no exista
**Estático.** No comprueban `cursor.rowcount`; siempre 200.
**Plan:** si `rowcount == 0` → `HTTPException(404)`.

---

## Lo que está bien (verificado)
- ✅ SQL parametrizado en todas las queries (sin inyección; el único f-string
  SQL de `webhooks.update_webhook` usa claves fijas controladas).
- ✅ CORS restringido a orígenes propios; `evil.com` no recibe allow-origin.
- ✅ Webhooks sí validan SSRF en remote mode (verificado: 400 con IP privada).
- ✅ `/api/reset` exige `?confirm=true` (verificado: 400 sin él).
- ✅ Passwords de proxy/Splunk enmascarados en GET (`***`).
- ✅ Frontend usa `esc()` consistentemente en datos de usuario/resultados.
- ✅ Herramientas wifi deshabilitadas en remote mode.
- ✅ Limpieza de scans huérfanos al arrancar y migración de esquema.
