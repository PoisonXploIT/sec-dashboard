"""WiFi 802.11 pcap tools: pcap_analyzer over synthetic captures (no network).

The synthetic capture is built with scapy and written with wrpcap: four
beacons (open, WPA2/RSN, open+WPS IE, hidden), one probe request, a deauth
burst (spec subtype 12) and an EAPOL 4-way handshake plus client data
frames, so the parser's SSID/security/WPS/deauth/EAPOL/client paths are
exercised offline. Management subtypes follow IEEE 802.11-2016 Table 10-3
(probe req=4, auth=11, deauth=12, action=13).
"""
import asyncio

import pytest
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11EltRSN,
    Dot11ProbeReq,
)
from scapy.packet import Raw
from scapy.utils import wrpcap

import backend.findings as findings
import backend.tools.pcap as pcap


def _run(coro):
    return asyncio.run(coro)


def _beacon(bssid: str, ssid: bytes, rsn: bool = False):
    els = [Dot11Elt(ID=0, info=ssid)]
    if rsn:
        els.append(Dot11EltRSN(version=1, group_cipher_suite=2,
                               pairwise_cipher_suites=[2], akm_suites=[0]))
    pkt = (Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                addr2=bssid, addr3=bssid) / Dot11Beacon())
    for e in els:
        pkt = pkt / e
    return pkt


def _eapol_key(key_type: int, secure: int, key_len: int) -> bytes:
    """Raw EAPOL-Key header (proto 0x0000, ver 1, descriptor 2).

    Offsets: +4..5 Key Information (pairwise bit = 1<<10, secure = 1<<7),
    +6 Key Type byte, +7 descriptor version, +8..9 key length.
    """
    info = ((1 if key_type else 0) << 10) | ((1 if secure else 0) << 7)
    return (b"\x00\x00\x01\x02" + info.to_bytes(2, "little")
            + bytes([key_type, 2]) + key_len.to_bytes(2, "little")
            + b"\x00" * 8)


def _data_frame(src: str, payload: bytes):
    return (Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff",
                 addr2=src, addr3="ff:ff:ff:ff:ff:ff") / Raw(load=payload))


STA = "dd:ee:ff:00:00:9a"  # client MAC (not a beaconing BSSID)

# LLC/SNAP-like prefix so the EAPOL signature sits past offset 24 of the
# frame, as in real monitor-mode captures.
_SNAP = b"\x00\x00\x03\x00\x01\x00" + (0).to_bytes(3, "little") \
    + (0x888e).to_bytes(2, "big")


@pytest.fixture(scope="module")
def pcap_file(tmp_path_factory):
    d = tmp_path_factory.mktemp("pcap")
    # WPS vendor IE: ID 221 (0xDF) is set on the Elt; info is the payload
    # after the IE header: OUI 00:03:7F + version byte + padding.
    wps_info = bytes([0x00, 0x03, 0x7f, 0x00, 0x01]) + b"\x00" * 21
    wps_beacon = _beacon("aa:bb:cc:00:00:03", b"WPSNet") / Dot11Elt(ID=221, info=wps_info)
    probe = (Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                   addr2="dd:ee:ff:00:00:01", addr3="dd:ee:ff:00:00:01") / Dot11ProbeReq())
    deauth = (Dot11(type=0, subtype=12, addr1="dd:ee:ff:00:00:01",
                   addr2="aa:bb:cc:00:00:99") / Dot11Deauth(reason=1))
    # Full 4-way handshake from the STA: M1 (pairwise, key data),
    # M2 (pairwise secure), M3 (group, key data), M4 (group, no key data).
    eapol = [
        _data_frame(STA, _SNAP + _eapol_key(1, 0, 32)),
        _data_frame(STA, _SNAP + _eapol_key(1, 1, 0)),
        _data_frame(STA, _SNAP + _eapol_key(0, 0, 32)),
        _data_frame(STA, _SNAP + _eapol_key(0, 1, 0)),
    ]
    # Two plain data frames from the STA (client list) and one from a
    # beaconing BSSID (must be excluded from clients).
    client_data = [
        _data_frame(STA, b"\x00" * 20),
        _data_frame(STA, b"\x01" * 20),
        _data_frame("aa:bb:cc:00:00:01", b"\x02" * 20),
    ]
    path = d / "synthetic.pcap"
    wrpcap(str(path), [
        _beacon("aa:bb:cc:00:00:01", b"OpenNet"),
        _beacon("aa:bb:cc:00:00:02", b"WPA2Net", rsn=True),
        wps_beacon,
        _beacon("aa:bb:cc:00:00:04", b""),  # hidden SSID
        probe,
    ] + [deauth] * 12 + eapol + client_data)
    return path


# ── parser / tool ───────────────────────────────────────────────

def test_parse_pcap_aggregates(pcap_file):
    data = pcap.parse_pcap(str(pcap_file))
    # 4 beacons + 1 probe + 12 deauth + 4 EAPOL data + 3 client data.
    assert data["n_frames"] == 24
    assert data["truncated"] is False
    assert data["n_80211"] == 24
    assert data["frame_types"]["mgmt"] == 17
    assert data["frame_types"]["data"] == 7
    assert data["mgmt_subtypes"]["beacon"] == 4
    # Spec subtypes: probe req = 4, deauth = 12.
    assert data["mgmt_subtypes"]["probe_req"] == 1
    assert data["deauth_count"] == 12

    ssids = {s["ssid"] for s in data["ssids"]}
    assert ssids == {"OpenNet", "WPA2Net", "WPSNet"}

    # OpenNet + WPSNet + hidden beacon without ciphers; WPA2Net is RSN.
    assert data["security"]["open"] == 3
    assert data["security"]["wpa2"] == 1
    assert data["security"]["legacy"] == 0

    # WPS vendor OUI 00:03:7F inside IE id 221 of the third beacon.
    assert data["wps_frames"] >= 1
    assert data["duration_s"] >= 0.0


def test_eapol_handshake_detection(pcap_file):
    data = pcap.parse_pcap(str(pcap_file))
    assert data["eapol_frames"] == 4
    msgs = data["handshake_msgs"]
    assert (msgs["m1"], msgs["m2"], msgs["m3"], msgs["m4"]) == (1, 1, 1, 1)
    assert data["wpa_handshake_seen"] is True


def test_hidden_ssid_detection(pcap_file):
    data = pcap.parse_pcap(str(pcap_file))
    assert data["hidden_bssid_count"] == 1
    assert [h["bssid"] for h in data["hidden_bssids"]] == ["aa:bb:cc:00:00:04"]


def test_client_list(pcap_file):
    data = pcap.parse_pcap(str(pcap_file))
    # STA MAC counted from 2 plain data frames + 4 EAPOL data frames;
    # the beaconing BSSID source is excluded.
    assert data["n_clients"] == 1
    assert data["clients"][0]["mac"] == STA
    assert data["clients"][0]["count"] == 6


def test_pcap_analyzer_async_success(pcap_file):
    result = _run(pcap.pcap_analyzer(str(pcap_file)))
    assert "error" not in result
    assert result["size_bytes"] > 0
    assert result["n_80211"] == 24
    # parse_pcap output is JSON-serializable by construction (int/str list).
    import json
    json.dumps(result)


def test_missing_file_is_clean_error(tmp_path):
    result = _run(pcap.pcap_analyzer(str(tmp_path / "nope.pcap")))
    assert "error" in result and "No such file" in result["error"]


def test_rejects_non_pcap_extension(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_bytes(b"not a pcap")
    result = _run(pcap.pcap_analyzer(str(f)))
    assert "error" in result and "Not a pcap file" in result["error"]


def test_corrupt_pcap_is_clean_error(tmp_path):
    f = tmp_path / "corrupt.pcap"
    f.write_bytes(b"PC\x0a\n" + b"\x00" * 16)  # truncated header, no frames
    result = _run(pcap.pcap_analyzer(str(f)))
    assert "error" in result


# ── adapter ─────────────────────────────────────────────────────

def _result(**over):
    base = {
        "file": "/x/synthetic.pcap", "size_bytes": 1234,
        "n_frames": 24, "truncated": False, "duration_s": 0.0,
        "n_80211": 24,
        "frame_types": {"mgmt": 17, "ctrl": 0, "data": 7},
        "mgmt_subtypes": {"beacon": 4, "probe_req": 1, "deauth": 12},
        "channels": [],
        "ssids": [{"ssid": "OpenNet", "count": 1}],
        "bssids": [{"bssid": "aa:bb:cc:00:00:01", "count": 1}],
        "security": {"open": 3, "wpa2": 1, "legacy": 0},
        "deauth_count": 12, "wps_frames": 3,
        "eapol_frames": 4,
        "handshake_msgs": {"m1": 1, "m2": 1, "m3": 1, "m4": 1},
        "wpa_handshake_seen": True,
        "hidden_bssid_count": 1,
        "hidden_bssids": [{"bssid": "aa:bb:cc:00:00:04", "count": 1}],
        "n_clients": 1,
        "clients": [{"mac": STA, "frames": 6}],
    }
    base.update(over)
    return base


def test_adapter_summary_info_and_zero_score():
    out = findings.extract_findings("pcap_analyzer", _result(), "/x/synthetic.pcap")
    assert len(out) >= 1
    info = next(f for f in out if f.severity is findings.Severity.INFO)
    assert "802.11 pcap analyzed" in info.title
    # Only INFO would score 0; here LOW/MEDIUM are present, so check the
    # INFO entry itself weighs nothing via its severity weight.
    assert findings.score_findings([info]) == 0


def test_adapter_open_nets_low():
    out = findings.extract_findings("pcap_analyzer", _result(), "/x.pcap")
    low = next(f for f in out if f.severity is findings.Severity.LOW)
    assert "open network" in low.title.lower()


def test_adapter_wps_and_deauth_medium():
    out = findings.extract_findings("pcap_analyzer", _result(), "/x.pcap")
    sevs = [f.severity for f in out]
    assert findings.Severity.MEDIUM in sevs
    titles = " ".join(f.title.lower() for f in out)
    assert "wps" in titles
    assert "deauthentication storm" in titles


def test_adapter_handshake_medium():
    out = findings.extract_findings("pcap_analyzer", _result(), "/x.pcap")
    hs = [f for f in out if "handshake" in f.title.lower()]
    assert len(hs) == 1
    assert hs[0].severity is findings.Severity.MEDIUM
    assert hs[0].evidence["eapol_frames"] == 4


def test_adapter_hidden_ssid_low():
    out = findings.extract_findings("pcap_analyzer", _result(), "/x.pcap")
    hid = [f for f in out if "hidden ssid" in f.title.lower()]
    assert len(hid) == 1
    assert hid[0].severity is findings.Severity.LOW


def test_adapter_quiet_capture_only_info():
    quiet = _result(security={"open": 0, "wpa2": 1, "legacy": 0},
                    deauth_count=0, wps_frames=0,
                    eapol_frames=0, wpa_handshake_seen=False,
                    hidden_bssid_count=0, hidden_bssids=[])
    out = findings.extract_findings("pcap_analyzer", quiet, "/x.pcap")
    assert len(out) == 1
    assert all(f.severity is findings.Severity.INFO for f in out)


def test_adapter_error_result_no_findings():
    out = findings.extract_findings(
        "pcap_analyzer", {"error": "No such file: /x"}, "/x")
    assert out == []


def test_adapter_caps_at_6():
    out = findings.extract_findings("pcap_analyzer", _result(), "/x.pcap")
    # INFO + handshake + open + wps + deauth + hidden = 6, the cap.
    assert len(out) <= 6
    assert len(out) == 6
