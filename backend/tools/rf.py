"""RF hardware tools — offline analysis of radio captures.

hackrf_cff_analyzer characterizes HackRF .cff captures (int8 I/Q interleaved,
no header) uploaded to the dashboard via /api/upload/cff. No live capture:
the file is recorded externally with hackrf_transfer and then analyzed here.

The 'target' parameter is the absolute path of the uploaded .cff file, not a
network target; this tool never opens the network. The heavy DSP runs in a
worker thread (asyncio.to_thread) so the event loop stays responsive.
"""
import asyncio
import os

from backend.tools import rf_parser

# Default sample rate of the capture protocol (hackrf_transfer -s 2000000).
DEFAULT_SAMPLE_RATE = 2_000_000


async def hackrf_cff_analyzer(target: str = "", profile: str = "keycard-433.92",
                              sample_rate: int = DEFAULT_SAMPLE_RATE, **kwargs) -> dict:
    """Analyze an uploaded HackRF .cff capture.

    target: absolute path to the .cff file (produced by /api/upload/cff).
    profile: band profile name (metadata + sanity; analysis is baseband).
    sample_rate: samples per second of the capture (default 2 MSPS, the
        capture protocol rate; overridable via params).
    max_demod: max packets to demodulate (params, clamped 1..500).

    Returns file metadata plus the full characterization from rf_parser:
    DC, dominant tones A/B, symbol timing Ts (+ replica cross-check),
    packet/sub-burst structure, clusters, FSK streams and the code status
    ("validado" | "pendiente_validacion" | None — regla 5).
    """
    if not target or not os.path.isfile(target):
        return {"error": f"No such file: {target}",
                "hint": "Upload a .cff capture first (POST /api/upload/cff)."}
    if profile not in rf_parser.PROFILES:
        return {"error": f"Unknown profile: {profile}",
                "profiles": sorted(rf_parser.PROFILES)}

    try:
        sr = int(sample_rate)
        if sr <= 0:
            raise ValueError("sample_rate must be > 0")
        max_demod = int(kwargs.get("max_demod", 200))
        max_demod = max(1, min(max_demod, 500))
        data = await asyncio.to_thread(rf_parser.analyze, target, sr, profile, max_demod)
    except (ValueError, OSError, MemoryError) as e:
        return {"error": f"Analysis failed: {e}"}

    size = os.path.getsize(target)
    out = {
        "file": target,
        "size_bytes": size,
        "sample_rate": sr,
        "duration_s": round(data["n_samples"] / sr, 6),
        "profile": profile,
        "center_freq_hz": rf_parser.PROFILES[profile][0],
    }
    out.update(data)
    return out
