"""WiFi 802.11 pcap tools: pcap_analyzer over synthetic captures (no network).

The synthetic capture is built with scapy and written with wrpcap: three
beacons (open, WPA2/RSN, open+WPS IE), one probe request and a deauth burst,
so the parser's SSID/security/WPS/deauth paths are exercised offline.
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


@pytest.fixture(scope="module")
def pcap_file(tmp_path_factory):
    d = tmp_path_factory.mktemp("pcap")
    # WPS vendor IE: ID 221 (0xDF) is set on the Elt; info is the payload
    # after the IE header: OUI 00:03:7F + version byte + padding.
    wps_info = bytes([0x00, 0x03, 0x7f, 0x00, 0x01]) + b"\x00" * 21
    wps_beacon = _beacon("aa:bb:cc:00:00:03", b"WPSNet") / Dot11Elt(ID=221, info=wps_info)
    probe = (Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff",
                   addr2="dd:ee:ff:00:00:01", addr3="dd:ee:ff:00:00:01") / Dot11ProbeReq())
    deauth = (Dot11(type=0, subtype=6, addr1="dd:ee:ff:00:00:01",
                   addr2="aa:bb:cc:00:00:99") / Dot11Deauth(reason=1))
    path = d / "synthetic.pcap"
    wrpcap(str(path), [
        _beacon("aa:bb:cc:00:00:01", b"OpenNet"),
        _beacon("aa:bb:cc:00:00:02", b"WPA2Net", rsn=True),
        wps_beacon,
        probe,
    ] + [deauth] * 12)
    return path


# ── parser / tool ───────────────────────────────────────────────

def test_parse_pcap_aggregates(pcap_file):
    data = pcap.parse_pcap(str(pcap_file))
    assert data["n_frames"] == 16
    assert data["truncated"] is False
    assert data["n_80211"] == 16
    # All synthetic frames are management (3 beacons + probe req + 12 deauth).
    assert data["frame_types"]["mgmt"] == 16
    assert data["frame_types"]["data"] == 0
    assert data["mgmt_subtypes"]["beacon"] == 3
    assert data["mgmt_subtypes"]["probe_req"] == 1
    assert data["deauth_count"] == 12

    ssids = {s["ssid"] for s in data["ssids"]}
    assert ssids == {"OpenNet", "WPA2Net", "WPSNet"}

    # OpenNet + WPSNet beacon without ciphers; WPA2Net is RSN.
    assert data["security"]["open"] == 2
    assert data["security"]["wpa2"] == 1
    assert data["security"]["legacy"] == 0

    # WPS vendor OUI 00:03:7F inside IE id 221 of the third beacon.
    assert data["wps_frames"] >= 1
    assert data["duration_s"] >= 0.0


def test_pcap_analyzer_async_success(pcap_file):
    result = _run(pcap.pcap_analyzer(str(pcap_file)))
    assert "error" not in result
    assert result["size_bytes"] > 0
    assert result["n_80211"] == 16
    # parse_pcap output is JSON-serializable by construction (int/str lists).
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
        "n_frames": 16, "truncated": False, "duration_s": 0.0,
        "n_80211": 16,
        "frame_types": {"mgmt": 4, "ctrl": 0, "data": 0},
        "mgmt_subtypes": {"beacon": 3, "probe_req": 1, "probe_resp": 0,
                          "deauth": 12, "action": 0},
        "channels": [],
        "ssids": [{"ssid": "OpenNet", "count": 1}],
        "bssids": [{"bssid": "aa:bb:cc:00:00:01", "count": 1}],
        "security": {"open": 2, "wpa2": 1, "legacy": 0},
        "deauth_count": 12, "wps_frames": 3,
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


def test_adapter_quiet_capture_only_info():
    quiet = _result(security={"open": 0, "wpa2": 1, "legacy": 0},
                    deauth_count=0, wps_frames=0)
    out = findings.extract_findings("pcap_analyzer", quiet, "/x.pcap")
    assert len(out) == 1
    assert all(f.severity is findings.Severity.INFO for f in out)


def test_adapter_error_result_no_findings():
    out = findings.extract_findings(
        "pcap_analyzer", {"error": "No such file: /x"}, "/x")
    assert out == []


def test_adapter_caps_at_4():
    out = findings.extract_findings("pcap_analyzer", _result(), "/x.pcap")
    assert len(out) <= 4
