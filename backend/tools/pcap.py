"""WiFi 802.11 offline pcap analysis (Marauder / Wireshark imports).

pcap_analyzer inspects .pcap/.pcapng files recorded externally — Marauder SD
exports, Wireshark monitor-mode captures. No live capture: scapy parses the
802.11 frames offline and this module only aggregates statistics; it never
opens the network. The file read runs in a worker thread (asyncio.to_thread)
so the event loop stays responsive on large captures.

Heuristics are documented per field: security buckets come from scapy's
beacon crypto classification, WPS is detected by the vendor OUI 00:03:7F in
IE id 221, and channels only appear when the capture carries RadioTap
headers (linktype IEEE 802.11 RADIO).
"""
import asyncio
import os
import re
import struct

from scapy.error import Scapy_Exception
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11ProbeReq,
    RadioTap,
)
from scapy.utils import rdpcap

# Safety cap: Marauder/Wireshark exports can be large; 200k frames is plenty
# for statistics and keeps memory bounded on the Railway tier.
MAX_FRAMES = 200_000
_TOP_N = 25

# WPS vendor-specific IE: id 221 (0xDD), any length, OUI 00:03:7F.
_WPS_IE_RE = re.compile(rb"\xdd[\x00-\xff]\x00\x03\x7f")

_MGMT_SUBTYPES = {8: "beacon", 12: "probe_req", 11: "probe_resp", 6: "deauth", 10: "action"}


def _security_bucket(crypto: set) -> str:
    """Map scapy's beacon crypto classification to a coarse bucket."""
    if any(str(c).startswith("WPA2") for c in crypto):
        return "wpa2"
    if any(str(c) == "OPN" for c in crypto):
        return "open"
    return "legacy"


def parse_pcap(path: str) -> dict:
    """Parse an 802.11 pcap and aggregate offline statistics (pure, sync)."""
    pkts = rdpcap(path, count=MAX_FRAMES)
    n_frames = len(pkts)

    frame_types = {"mgmt": 0, "ctrl": 0, "data": 0}
    mgmt_subtypes = {k: 0 for k in _MGMT_SUBTYPES.values()}
    channels: set[int] = set()
    ssid_count: dict[str, int] = {}
    bssid_count: dict[str, int] = {}
    bssid_crypto: dict[str, set] = {}
    deauth_count = 0
    wps_frames = 0

    for pkt in pkts:
        if not pkt.haslayer(Dot11):
            continue
        d11 = pkt[Dot11]
        t = int(d11.type)
        if t == 0:
            frame_types["mgmt"] += 1
            st = _MGMT_SUBTYPES.get(int(d11.subtype))
            if st:
                mgmt_subtypes[st] += 1
        elif t == 1:
            frame_types["ctrl"] += 1
        else:
            frame_types["data"] += 1

        rt = pkt.getlayer(RadioTap)
        if rt is not None and int(rt.Channel) > 0:
            channels.add(int(rt.Channel))

        raw = bytes(pkt)
        if _WPS_IE_RE.search(raw):
            wps_frames += 1

        be = pkt.getlayer(Dot11Beacon)
        if be is not None and hasattr(be, "network_stats"):
            stats = be.network_stats()
            ssid = stats.get("ssid")
            if ssid:
                ssid_count[ssid] = ssid_count.get(ssid, 0) + 1
            bssid = str(d11.addr2)
            bssid_count[bssid] = bssid_count.get(bssid, 0) + 1
            crypto = stats.get("crypto", {"OPN"})
            bssid_crypto.setdefault(bssid, set()).update(crypto)

        pr = pkt.getlayer(Dot11ProbeReq)
        if pr is not None and hasattr(pr, "network_stats"):
            ssid = pr.network_stats().get("ssid")
            if ssid:
                ssid_count[ssid] = ssid_count.get(ssid, 0) + 1

    security = {"open": 0, "wpa2": 0, "legacy": 0}
    for bssid, crypto in bssid_crypto.items():
        security[_security_bucket(crypto)] += 1

    def _top(counter: dict, key: str) -> list[dict]:
        items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:_TOP_N]
        return [{key: k, "count": int(v)} for k, v in items]

    duration_s = 0.0
    if n_frames:
        first = float(pkts[0].time)
        last = float(pkts[-1].time)
        duration_s = max(0.0, last - first)

    return {
        "n_frames": int(n_frames),
        "truncated": n_frames >= MAX_FRAMES,
        "duration_s": round(duration_s, 6),
        "n_80211": frame_types["mgmt"] + frame_types["ctrl"] + frame_types["data"],
        "frame_types": {k: int(v) for k, v in frame_types.items()},
        "mgmt_subtypes": {k: int(v) for k, v in mgmt_subtypes.items()},
        "channels": sorted(int(c) for c in channels)[:50],
        "ssids": _top(ssid_count, "ssid"),
        "bssids": _top(bssid_count, "bssid"),
        "security": security,
        "deauth_count": int(mgmt_subtypes["deauth"]),
        "wps_frames": int(wps_frames),
    }


async def pcap_analyzer(target: str = "", **kwargs) -> dict:
    """Analyze an uploaded 802.11 .pcap/.pcapng capture.

    target: absolute path to the pcap file (produced by /api/upload/pcap).
    Returns file metadata plus aggregate statistics from parse_pcap.
    """
    if not target or not os.path.isfile(target):
        return {"error": f"No such file: {target}",
                "hint": "Upload a .pcap/.pcapng capture first (POST /api/upload/pcap)."}
    name = target.lower()
    if not name.endswith((".pcap", ".pcapng", ".cap")):
        return {"error": f"Not a pcap file: {target}",
                "hint": "Accepted extensions: .pcap, .pcapng, .cap"}

    try:
        data = await asyncio.to_thread(parse_pcap, target)
    except (OSError, MemoryError, Scapy_Exception, struct.error, ValueError, OverflowError) as e:
        return {"error": f"Analysis failed: {e}"}

    out = {"file": target, "size_bytes": os.path.getsize(target)}
    out.update(data)
    return out
