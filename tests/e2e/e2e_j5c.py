"""E2E J5c: scan sammideblas.com -> PDF with Jev verdicts + local LLM explanations.

Server must be on :8799 with Jev and local LLM configured (in-memory).
No new dependencies: stdlib only.
"""
import json
import re
import time
import urllib.request
import zlib

BASE = "http://127.0.0.1:8799"


def api(path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return r.status, r.read()


def pdf_text(data: bytes) -> str:
    chunks = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        try:
            dec = zlib.decompress(m.group(1))
        except zlib.error:
            continue
        chunks.extend(re.findall(rb"\(((?:[^()\\]|\\.)*)\)", dec))
    return " ".join(t.decode("latin-1") for t in chunks)


status, raw = api("/api/scans", "POST", {"target_id": 3, "tool": "header_analyzer"})
created = json.loads(raw)
scan_id = created.get("scan_id") or (created.get("id") if isinstance(created, dict) else None)
print("scan created:", scan_id)

for _ in range(120):
    time.sleep(5)
    _, raw = api(f"/api/scans/{scan_id}")
    s = json.loads(raw)
    if s["status"] in ("completed", "failed"):
        break
assert s["status"] == "completed", f"scan ended {s['status']}"
result = json.loads(s["result"])
jev = result.get("jev") or {}
print("jev:", jev.get("status"), jev.get("model"),
      "verdicts:", len(jev.get("verdicts") or {}))

t0 = time.time()
_, pdf_bytes = api(f"/api/scans/{scan_id}/export/pdf")
dt = time.time() - t0
text = pdf_text(pdf_bytes).replace("\\(", "(").replace("\\)", ")")
print(f"pdf: {len(pdf_bytes)} bytes in {dt:.0f}s")

assert "AI Verdicts (Jev)" in text, "missing Jev section"
assert "Triage: accion requerida" in text, "missing triage section"
assert "Explicaciones LLM local" in text, "missing LLM explanations section"
# Spanish reference-only fields must be present with content.
for marker in ("Resumen:", "Porque:", "Sugerencia:"):
    assert marker in text, f"missing {marker}"
open("/tmp/e2e_j5c_scan.pdf", "wb").write(pdf_bytes)
print("OK: PDF saved to /tmp/e2e_j5c_scan.pdf")
