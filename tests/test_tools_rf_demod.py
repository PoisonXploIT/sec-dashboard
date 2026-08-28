"""Regression tests for FSK demodulation with a synthetic two-tone signal.

The synthetic capture is generated offline (no network): silence + bursts of
known bits, each bit = Ts samples at tone A ('0') or B ('1'), int8 I/Q
interleaved exactly as a .cff file. Two layers:

- unit: demod_packet recovers the known bits exactly on a clean segment;
- end-to-end: analyze() on a synthetic .cff finds structure, tones and runs
  the full pipeline (the Ts estimator is pinned to its search space here;
  its quality on real captures stays PENDIENTE VALIDACION per regla 5).
"""
import math

import numpy as np
import pytest

from backend.tools import rf_parser


SR = 200_000          # sample rate of the synthetic capture
TS = 1e-3            # symbol period: 1 ms -> 200 samples/symbol at SR
FA, FB = 30_000.0, 50_000.0   # tone A ('0') / tone B ('1'), both above center
AMP = 60             # int8 amplitude (floor is silence, thr=20 clears it)

# Fixed 40-bit pattern; Q is a cyclic shift of P by one symbol.
P = "0110100101110010101011001011010100110101"
assert len(P) == 40
Q = P[1:] + P[0]


def _tone_samples(f, n):
    t = np.arange(n) / SR
    x = AMP * np.exp(2j * math.pi * f * t)
    return x.real.astype(np.int8), x.imag.astype(np.int8)


def _burst(bits):
    """I/Q int8 arrays for a burst: Ts per bit, tone A='0', B='1'."""
    i_parts, q_parts = [], []
    for b in bits:
        f = FB if b == "1" else FA
        i, q = _tone_samples(f, int(TS * SR))
        i_parts.append(i)
        q_parts.append(q)
    return np.concatenate(i_parts), np.concatenate(q_parts)


def _silence(n):
    """Silent floor with light quantization noise (real .cff never is exact 0)."""
    pat = np.array([1, -1, 2, -2], dtype=np.int8)
    noise = np.resize(pat, n)
    return noise.copy(), noise[::-1].copy()


@pytest.fixture(scope="module")
def synthetic_cff(tmp_path_factory):
    """One .cff: silence + 4 bursts (P, Q, Q, Q) separated by gaps."""
    chunks = [_silence(int(0.150 * SR))]
    for bits in (P, Q, Q, Q):
        chunks.append(_burst(bits))
        chunks.append(_silence(int(0.080 * SR)))
    i = np.concatenate([c[0] for c in chunks])
    q = np.concatenate([c[1] for c in chunks])
    path = tmp_path_factory.mktemp("fsk") / "synth.cff"
    # interleave I/Q per the .cff format (I0 Q0 I1 Q1 ...)
    raw = np.empty(2 * len(i), dtype=np.int8)
    raw[0::2] = i
    raw[1::2] = q
    with open(path, "wb") as f:
        f.write(raw.tobytes())
    return str(path)


def test_demod_packet_recovers_known_bits():
    i, q = _burst(P)
    x = (i.astype(np.float32) + 1j * q.astype(np.float32)).astype(np.complex64)
    bits, ea, eb = rf_parser.demod_packet(x, FA, FB, TS, SR)
    assert bits is not None
    # clean signal: exact recovery of the known pattern
    assert bits == P
    assert ea is not None and eb is not None


def test_analyze_synthetic_fsk_cff(synthetic_cff):
    res = rf_parser.analyze(synthetic_cff, SR, "keycard-433.92")
    # structure: 4 packets, each ~40 ms (40 symbols x 1 ms)
    assert res["n_packets"] == 4
    # tones recovered at the center offsets used to generate
    assert abs(res["tone_a_khz"] - FA / 1e3) < 2.0
    assert abs(res["tone_b_khz"] - FB / 1e3) < 2.0
    # symbol timing found (search space 60 us .. 2 ms)
    assert res["ts_us"] is not None
    assert 60e-6 <= res["ts_us"] * 1e-6 <= 2e-3 * 1.01
    # demod ran on the repeated bursts: top stream repeats 3x (bursts 2-4),
    # burst 1 (P) is the runner-up.
    streams = res["streams"]
    assert len(streams) >= 2
    assert streams[0]["count"] == 3
    assert streams[1]["count"] == 1
    # the stability gate was reached (decision made on the repeated streams)
    assert res["code_status"] in ("validado", "pendiente_validacion")
