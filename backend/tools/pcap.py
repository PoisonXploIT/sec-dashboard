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

EAPOL handshake detection parses the EAPOL-Key header from raw frame bytes
(scapy does not auto-bind Dot11 -> LLC/SNAP -> EAPOL): signature proto
0x0000 + version 1 + key descriptor 2, searched after the 802.11 header.
Message number is inferred identically for legacy WPA and RSN: pairwise
frames (Key Type byte 1 or the Key Information pairwise bit) split on the
Secure bit (M1 unsecure, M2 secure); group frames (Key Type 0) split on key
data presence (M3 carries key data, M4 does not).

Client list: unique transmitter MACs (addr2) of data frames plus sources of
assoc-req/auth management frames, excluding broadcast and beaconing BSSIDs.
An AP that never beacons in the capture is indistinguishable from a client
and will appear here; treat the list as an estimate.
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

# IEEE 802.11-2016 Table 10-3 management subtypes (matches scapy's own table).
_MGMT_SUBTYPES = {
    0: "assoc_req", 1: "assoc_resp", 2: "reassoc_req", 3: "reassoc_resp",
    4: "probe_req", 5: "probe_resp", 6: "timing_adv", 8: "beacon",
    9: "atim", 10: "disassoc", 11: "auth", 12: "deauth", 13: "action",
}

# EAPOL-Key header signature (IEEE 802.1X): protocol 0x0000, version 1,
# key descriptor 2. Offsets from the signature: +4..5 Key Information,
# +6 Key Type byte (legacy WPA: 1-4 = M#; RSN: 0 group / 1 pairwise),
# +8..9 Key Length.
_EAPOL_SIG = b"\x00\x00\x01\x02"
_BROADCAST = "ff:ff:ff:ff:ff:ff"


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
    hidden_beacons: dict[str, int] = {}
    bssid_crypto: dict[str, set] = {}
    deauth_count = 0
    wps_frames = 0
    eapol_frames = 0
    handshake_msgs = {1: 0, 2: 0, 3: 0, 4: 0}

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
        if rt is not None:
            ch = rt.Channel
            if ch is not None and int(ch) > 0:
                channels.add(int(ch))

        raw = bytes(pkt)
        if _WPS_IE_RE.search(raw):
            wps_frames += 1

        if t == 2:  # data frame: look for an EAPOL-Key in the payload
            idx = raw.find(_EAPOL_SIG, 24)
            if idx != -1 and len(raw) >= idx + 10:
                p = raw[idx:]
                info = p[4] | (p[5] << 8)
                kt = p[6]
                pairwise = kt == 1 or ((info >> 10) & 1) == 1
                secure = (info >> 7) & 1
                klen = p[8] | (p[9] << 8)
                if pairwise:
                    msg = 1 if not secure else 2
                else:  # group key
                    msg = 3 if klen > 0 else 4
                eapol_frames += 1
                handshake_msgs[msg] += 1

        be = pkt.getlayer(Dot11Beacon)
        if be is not None and hasattr(be, "network_stats"):
            stats = be.network_stats()
            ssid = stats.get("ssid")
            if ssid:
                ssid_count[ssid] = ssid_count.get(ssid, 0) + 1
            bssid = str(d11.addr2)
            bssid_count[bssid] = bssid_count.get(bssid, 0) + 1
            if not ssid:
                hidden_beacons[bssid] = hidden_beacons.get(bssid, 0) + 1
            crypto = stats.get("crypto", {"OPN"})
            bssid_crypto.setdefault(bssid, set()).update(crypto)

        pr = pkt.getlayer(Dot11ProbeReq)
        if pr is not None and hasattr(pr, "network_stats"):
            ssid = pr.network_stats().get("ssid")
            if ssid:
                ssid_count[ssid] = ssid_count.get(ssid, 0) + 1

    # Clients: STA transmitters of data frames + assoc-req/auth sources,
    # minus broadcast and beaconing BSSIDs (second pass, pure aggregation).
    beacon_bssids = set(bssid_count)
    clients: dict[str, int] = {}
    for pkt in pkts:
        if not pkt.haslayer(Dot11):
            continue
        d11 = pkt[Dot11]
        src = str(d11.addr2)
        if src == _BROADCAST or src in beacon_bssids:
            continue
        t = int(d11.type)
        if t == 2:
            clients[src] = clients.get(src, 0) + 1
        elif t == 0 and int(d11.subtype) in (0, 11):  # assoc_req / auth
            clients[src] = clients.get(src, 0) + 1

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
        "eapol_frames": int(eapol_frames),
        "handshake_msgs": {f"m{i}": int(v) for i, v in handshake_msgs.items()},
        "wpa_handshake_seen": bool(
            (handshake_msgs[1] and handshake_msgs[2])
            or (handshake_msgs[3] and handshake_msgs[4])
        ),
        "hidden_bssid_count": len(hidden_beacons),
        "hidden_bssids": _top(hidden_beacons, "bssid"),
        "n_clients": len(clients),
        "clients": _top(clients, "mac"),
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
