"""RF hardware tools — offline analysis of radio captures.

hackrf_cff_analyzer characterizes HackRF .cff captures (int8 I/Q interleaved,
no header) uploaded to the dashboard via /api/upload/cff. No live capture:
the file is recorded externally with hackrf_transfer and then analyzed here.

The 'target' parameter is the absolute path of the uploaded .cff file, not a
network target; this tool never opens the network.
"""
import os


# Default sample rate of the capture protocol (hackrf_transfer -s 2000000).
DEFAULT_SAMPLE_RATE = 2_000_000

# Band profiles: name -> center frequency in Hz. Metadata + sanity only:
# the analysis runs in baseband relative to the capture center, so the
# profile never changes the DSP, it only labels the result and warns when
# a center lies outside the declared hardware range (Mayhem HackRF/SDR
# mode = 1 MHz - 6 GHz).
PROFILES: dict[str, int] = {
    "keycard-433.92": 433_920_000,   # Sandero III 2022 key (own dataset)
    "subghz-315": 315_000_000,       # ISM 300-348 MHz EU
    "subghz-434.42": 434_420_000,    # ISM 433-434 MHz EU, top edge
    "subghz-868.3": 868_310_000,     # SRD 868-870 MHz EU
    "subghz-915": 915_000_000,       # ISM 902-928 MHz US
    "wifi-2400": 2_400_000_000,      # WiFi ch1 2.4 GHz (raw spectrum)
    "wifi-2442": 2_442_000_000,      # WiFi ch13 2.4 GHz (raw spectrum)
    "wifi-5180": 5_180_000_000,      # WiFi 5 GHz (raw spectrum)
}


async def hackrf_cff_analyzer(target: str = "", profile: str = "keycard-433.92",
                              sample_rate: int = DEFAULT_SAMPLE_RATE, **kwargs) -> dict:
    """Analyze an uploaded HackRF .cff capture.

    target: absolute path to the .cff file (produced by /api/upload/cff).
    profile: band profile name (metadata + sanity; analysis is baseband).
    sample_rate: samples per second of the capture (default 2 MSPS, the
        capture protocol rate; overridable via params).

    Returns metadata for now: file size, sample rate, estimated duration
    (bytes / 2 / sample_rate, int8 I/Q interleaved) and the profile center
    frequency.
    """
    if not target or not os.path.isfile(target):
        return {"error": f"No such file: {target}",
                "hint": "Upload a .cff capture first (POST /api/upload/cff)."}
    if profile not in PROFILES:
        return {"error": f"Unknown profile: {profile}",
                "profiles": sorted(PROFILES)}

    size = os.path.getsize(target)
    duration_s = round(size / 2 / sample_rate, 6) if sample_rate else 0.0
    return {
        "file": target,
        "size_bytes": size,
        "sample_rate": sample_rate,
        "duration_s": duration_s,
        "profile": profile,
        "center_freq_hz": PROFILES[profile],
    }
