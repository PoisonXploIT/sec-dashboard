"""RF tools: hackrf_cff_analyzer over synthetic .cff files (no network)."""
import asyncio

import backend.findings as findings
import backend.tools.rf as rf


def _run(coro):
    return asyncio.run(coro)


def _write_cff(path, n_samples: int = 1000) -> bytes:
    """Write a synthetic .cff: int8 I/Q interleaved, 2 bytes per sample."""
    raw = bytearray()
    for k in range(n_samples):
        i = (k * 7 + 3) % 251 - 125              # I: pseudo-random int8
        q = (k * 11 + 5) % 249 - 124             # Q: pseudo-random int8
        raw.append(i & 0xFF)
        raw.append(q & 0xFF)
    data = bytes(raw)
    path.write_bytes(data)
    return data


# ── tool (Paso A: metadata only) ────────────────────────────────

def test_metadata_on_synthetic_cff(tmp_path):
    f = tmp_path / "synthetic.cff"
    _write_cff(f, 1000)
    result = _run(rf.hackrf_cff_analyzer(str(f), profile="keycard-433.92"))
    assert "error" not in result
    assert result["size_bytes"] == 2000
    assert result["sample_rate"] == rf.DEFAULT_SAMPLE_RATE
    # duration = bytes / 2 / sample_rate = 1000 samples / 2e6
    assert abs(result["duration_s"] - 1000 / 2_000_000) < 1e-9
    assert result["profile"] == "keycard-433.92"
    assert result["center_freq_hz"] == 433_920_000


def test_sample_rate_overridable(tmp_path):
    f = tmp_path / "synthetic.cff"
    _write_cff(f, 1000)
    result = _run(rf.hackrf_cff_analyzer(str(f), sample_rate=4_000_000))
    assert result["sample_rate"] == 4_000_000
    assert abs(result["duration_s"] - 1000 / 4_000_000) < 1e-9


def test_missing_file_is_clean_error(tmp_path):
    result = _run(rf.hackrf_cff_analyzer(str(tmp_path / "nope.cff")))
    assert "error" in result and "No such file" in result["error"]


def test_unknown_profile_lists_available(tmp_path):
    f = tmp_path / "synthetic.cff"
    _write_cff(f)
    result = _run(rf.hackrf_cff_analyzer(str(f), profile="nope"))
    assert "error" in result and "Unknown profile" in result["error"]
    assert "keycard-433.92" in result["profiles"]


# ── adapter ─────────────────────────────────────────────────────

def test_adapter_metadata_info_and_zero_score():
    target = "/tmp/x.cff"
    result = {
        "file": target, "size_bytes": 2000, "sample_rate": 2_000_000,
        "duration_s": 0.0005, "profile": "keycard-433.92",
        "center_freq_hz": 433_920_000,
    }
    out = findings.extract_findings("hackrf_cff_analyzer", result, target)
    assert len(out) == 1
    assert out[0].severity is findings.Severity.INFO
    # INFO weighs 0 in the score (SEVERITY_WEIGHT).
    assert findings.score_findings(out) == 0


def test_adapter_error_result_no_findings():
    out = findings.extract_findings(
        "hackrf_cff_analyzer", {"error": "No such file: /x"}, "/x")
    assert out == []


def test_adapter_pendiente_validacion_is_low():
    result = {
        "size_bytes": 100, "duration_s": 0.0, "sample_rate": 2_000_000,
        "profile": "keycard-433.92", "center_freq_hz": 433_920_000,
        "n_packets": 12,
        "subbursts": {"n": 4},
        "code_status": "pendiente_validacion",
        "streams": [{"bits": "11110101", "count": 3}],
    }
    out = findings.extract_findings("hackrf_cff_analyzer", result, "/x.cff")
    sevs = [f.severity for f in out]
    assert findings.Severity.LOW in sevs
    low = next(f for f in out if f.severity is findings.Severity.LOW)
    assert "not yet validated" in low.title


def test_adapter_validado_is_medium():
    result = {
        "size_bytes": 100, "duration_s": 0.0, "sample_rate": 2_000_000,
        "profile": "keycard-433.92", "center_freq_hz": 433_920_000,
        "n_packets": 12, "subbursts": {"n": 4},
        "code_status": "validado",
        "streams": [{"bits": "11110101", "count": 5}],
    }
    out = findings.extract_findings("hackrf_cff_analyzer", result, "/x.cff")
    sevs = [f.severity for f in out]
    assert findings.Severity.MEDIUM in sevs
    med = next(f for f in out if f.severity is findings.Severity.MEDIUM)
    assert "clonable" in med.title.lower() or "recovered" in med.title.lower()


def test_adapter_caps_at_4():
    result = {
        "size_bytes": 100, "duration_s": 0.0, "sample_rate": 2_000_000,
        "profile": "keycard-433.92", "center_freq_hz": 433_920_000,
        "n_packets": 12, "subbursts": {"n": 4},
        "code_status": "validado",
    }
    out = findings.extract_findings("hackrf_cff_analyzer", result, "/x.cff")
    assert len(out) <= 4
