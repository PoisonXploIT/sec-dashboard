"""E2E J5d: nuclear pipeline on sammideblas.com.

Verifies the new flow: LLM explanations are generated at run completion
(stored in the result), then PDF and JSON exports both carry them and the
PDF export itself is instant (no LLM calls at export time).
"""
import json
import re
import time
import urllib.request
import zlib

BASE = "http://127.0.0.1:8799"
PID = 14


def api(path, timeout=600):
    req = urllib.request.Request(BASE + path)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def pdf_text(data: bytes) -> str:
    chunks = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        try:
            dec = zlib.decompress(m.group(1))
        except zlib.error:
            continue
        chunks.extend(re.findall(rb"\(((?:[^()\\]|\\.)*)\)", dec))
    return " ".join(t.decode("latin-1") for t in chunks)


t0 = time.time()
while True:
    s = json.loads(api(f"/api/pipelines/{PID}/result"))
    if s["status"] in ("completed", "failed"):
        break
    if time.time() - t0 > 2400:
        raise SystemExit("TIMEOUT waiting for pipeline")
    time.sleep(15)

print("pipeline status:", s["status"], f"({time.time() - t0:.0f}s)")
assert s["status"] == "completed", s["status"]
result = s["result"] if isinstance(s["result"], dict) else json.loads(s["result"])
jev = result.get("jev") or {}
print("jev:", jev.get("status"), jev.get("model"),
      "verdicts:", len(jev.get("verdicts") or {}))

# J5d: explanations must already be in the run result (generated before export).
expls = result.get("llm_explanations")
assert isinstance(expls, list) and expls, "missing llm_explanations in result"
print("llm_explanations in result:", len(expls),
      "| first:", expls[0].get("title"), "| model:", expls[0].get("model"))

t1 = time.time()
pdf_bytes = api(f"/api/pipelines/{PID}/export/pdf")
pdf_dt = time.time() - t1
text = pdf_text(pdf_bytes).replace("\\(", "(").replace("\\)", ")")
print(f"pdf: {len(pdf_bytes)} bytes in {pdf_dt:.1f}s (must be fast now)")
assert pdf_dt < 30, "PDF export took too long; LLM should not run at export time"
assert "AI Verdicts (Jev)" in text, "missing Jev section"
assert "Triage: accion requerida" in text, "missing triage section"
assert "Explicaciones LLM local" in text, "missing LLM explanations section"
for marker in ("Resumen:", "Porque:", "Sugerencia:"):
    assert marker in text, f"missing {marker}"

t2 = time.time()
json_bytes = api(f"/api/pipelines/{PID}/export/json")
jdata = json.loads(json_bytes)
jres = jdata.get("result") if isinstance(jdata, dict) else None
jexpls = (jres or {}).get("llm_explanations") if isinstance(jres, dict) else None
print(f"json: {len(json_bytes)} bytes in {time.time() - t2:.1f}s; "
      f"llm_explanations in json:", len(jexpls or []))
assert jexpls and len(jexpls) == len(expls), "JSON export missing llm_explanations"

open(r"C:\Users\Sammi\Temp\informe-nuclear-sammideblas.pdf", "wb").write(pdf_bytes)
print("OK saved C:\\Users\\Sammi\\Temp\\informe-nuclear-sammideblas.pdf")
