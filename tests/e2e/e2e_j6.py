"""E2E J6: per-run AI options + Spanish explanations in every format.

Runs against the live server on :8799 (real Jev API + local LLM on :8099):
  A) scan header_analyzer with jev+llm   -> explanations in result, PDF, JSON, CSV
  B) scan header_analyzer with llm:false -> no explanations anywhere (classic)
  C) fast pipeline with jev+llm          -> same checks on pipeline exports
"""
import csv
import io
import json
import re
import time
import urllib.request
import zlib

BASE = "http://127.0.0.1:8799"


def post(path, body, timeout=600):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def get(path, timeout=120):
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


def csv_header(text: str):
    return next(csv.reader(io.StringIO(text)))


def scan_result(scan_id):
    while True:
        data = json.loads(get(f"/api/scans/{scan_id}"))
        if data["status"] in ("completed", "failed"):
            return data
        time.sleep(2)


# ── A) scan with jev + llm ──────────────────────────────────────────────
t0 = time.time()
a = post("/api/scans", {"target_id": 3, "tool": "header_analyzer",
                        "jev": True, "llm": True})
res_a = a["result"] if isinstance(a["result"], dict) else json.loads(a["result"])
expls_a = res_a.get("llm_explanations")
print(f"A) scan {a['scan_id']} jev={res_a.get('jev', {}).get('status')} "
      f"llm_expl={len(expls_a or [])} ({time.time() - t0:.0f}s)")
assert res_a["jev"]["status"] == "ok"
assert isinstance(expls_a, list) and expls_a
first = next(e for e in expls_a if e.get("resumen"))
assert first["resumen"] and first["porque"] and first["sugerencia"]

pdf_a = pdf_text(get(f"/api/scans/{a['scan_id']}/export/pdf")).replace("\\", "")
json_a = json.loads(get(f"/api/scans/{a['scan_id']}/export/json"))
csv_a = get(f"/api/scans/{a['scan_id']}/export/csv").decode("utf-8-sig")
probe = " ".join(first["resumen"].split()[:8])
assert "Local LLM Explanations" in pdf_a and probe in pdf_a, "PDF missing Spanish explanation"
assert json_a.get("llm_explanations", [{}])[0].get("resumen"), "JSON missing llm_explanations"
hdr_a = csv_header(csv_a)
assert "llm_resumen" in hdr_a and "llm_porque" in hdr_a and "llm_sugerencia" in hdr_a, "CSV missing llm columns"
rows_a = list(csv.reader(io.StringIO(csv_a)))
i_sum = hdr_a.index("llm_resumen")
assert any(r[i_sum] for r in rows_a[1:]), "CSV llm column empty"
print("   PDF/JSON/CSV all carry the Spanish explanation")

# ── B) scan with llm opt-out (classic output) ───────────────────────────
t0 = time.time()
b = post("/api/scans", {"target_id": 3, "tool": "header_analyzer",
                        "jev": True, "llm": False})
res_b = b["result"] if isinstance(b["result"], dict) else json.loads(b["result"])
print(f"B) scan {b['scan_id']} jev={res_b.get('jev', {}).get('status')} "
      f"llm_expl={'NONE' if 'llm_explanations' not in res_b else 'PRESENT'} ({time.time() - t0:.0f}s)")
assert res_b["jev"]["status"] == "ok"
assert "llm_explanations" not in res_b, "opt-out must leave no llm_explanations"
json_b = json.loads(get(f"/api/scans/{b['scan_id']}/export/json"))
csv_b = get(f"/api/scans/{b['scan_id']}/export/csv").decode("utf-8-sig")
assert "llm_explanations" not in json_b, "JSON must not carry llm_explanations"
assert "llm_resumen" not in csv_header(csv_b), "CSV must not have llm columns"
pdf_b = pdf_text(get(f"/api/scans/{b['scan_id']}/export/pdf"))
assert "Local LLM Explanations" not in pdf_b, "PDF must not have the section"
print("   opt-out run: classic output everywhere (no LLM data)")

# ── C) fast pipeline with jev + llm ─────────────────────────────────────
t0 = time.time()
c = post("/api/pipelines", {"target_id": 3, "mode": "fast",
                            "jev": True, "llm": True})
pid = c["pipeline_id"]
while True:
    s = json.loads(get(f"/api/pipelines/{pid}/result"))
    if s["status"] in ("completed", "failed"):
        break
    time.sleep(10)
res_c = s["result"] if isinstance(s["result"], dict) else json.loads(s["result"])
expls_c = res_c.get("llm_explanations")
print(f"C) pipeline {pid} status={s['status']} "
      f"jev={res_c.get('jev', {}).get('status')} llm_expl={len(expls_c or [])} "
      f"({time.time() - t0:.0f}s)")
assert s["status"] == "completed"
assert res_c["jev"]["status"] == "ok"
assert isinstance(expls_c, list) and expls_c

json_c = json.loads(get(f"/api/pipelines/{pid}/export/json"))
csv_c = get(f"/api/pipelines/{pid}/export/csv").decode("utf-8-sig")
pdf_c = pdf_text(get(f"/api/pipelines/{pid}/export/pdf")).replace("\\", "")
assert json_c.get("llm_explanations"), "pipeline JSON missing llm_explanations"
assert "llm_sugerencia" in csv_header(csv_c), "pipeline CSV missing llm columns"
assert "Local LLM Explanations" in pdf_c, "pipeline PDF missing section"
print("   pipeline PDF/JSON/CSV all carry the Spanish explanations")

print("E2E J6 OK")
