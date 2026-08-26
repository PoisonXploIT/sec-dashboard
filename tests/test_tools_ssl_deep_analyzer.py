"""F1-SSL: ssl_deep_analyzer tool + findings adapter (no network)."""
import asyncio
import struct

import backend.findings as findings
import backend.tools.network as network


def _run(coro):
    return asyncio.run(coro)


# ── HSTS header parsing ────────────────────────────────────────
def test_parse_hsts_full_value():
    out = network._parse_hsts("max-age=63072000; includeSubDomains; preload")
    assert out["max_age"] == 63072000
    assert out["include_subdomains"] is True
    assert out["preload"] is True


def test_parse_hsts_quoted_and_garbage():
    assert network._parse_hsts('max-age="31536000"')["max_age"] == 31536000
    assert network._parse_hsts("")["max_age"] is None
    assert network._parse_hsts("max-age=abc")["max_age"] is None


# ── grade engine ────────────────────────────────────────────────
def _checks(pairs):
    return [{"id": i, "status": s, "detail": ""} for i, s in pairs]


def test_grade_clean_is_a_plus():
    assert network._compute_grade(_checks([("tls_legacy", "pass"),
                                           ("hsts_missing", "pass")])) == "A+"


def test_grade_empty_checks_none():
    assert network._compute_grade([]) is None


def test_grade_caps_and_worst_wins():
    assert network._compute_grade(_checks([("tls_legacy", "fail")])) == "F"
    assert network._compute_grade(_checks([("weak_cipher", "fail"),
                                           ("hsts_missing", "fail")])) == "F"
    assert network._compute_grade(_checks([("no_forward_secrecy", "fail")])) == "B+"
    assert network._compute_grade(_checks([("hsts_missing", "fail")])) == "A"
    assert network._compute_grade(_checks([("hsts_short", "fail")])) == "A-"
    # cert_expired (D) is worse than self_signed (C): D must win.
    assert network._compute_grade(_checks([("self_signed", "fail"),
                                           ("cert_expired", "fail")])) == "D"


# ── checks builder ──────────────────────────────────────────────
def test_build_checks_statuses():
    versions = {"1.0": True, "1.1": False, "1.2": True, "1.3": True,
                "negotiated": {"version": "TLSv1.3",
                               "cipher": "TLSv1.3 ECDHE-RSA-AES256-GCM-SHA384"}}
    hsts = {"present": False, "max_age": None,
            "include_subdomains": False, "preload": False}
    ocsp = {"stapling": "unknown", "responder": None}
    checks = network._build_ssl_checks(versions, ["TLSv1 DES-CBC-SHA"],
                                       hsts, ocsp, None)
    by_id = {c["id"]: c["status"] for c in checks}
    assert by_id["tls_legacy"] == "fail"
    assert by_id["weak_cipher"] == "fail"
    assert by_id["no_forward_secrecy"] == "pass"  # ECDHE in negotiated cipher
    assert by_id["self_signed"] == "warn"        # cert unreadable
    assert by_id["cert_expired"] == "warn"
    assert by_id["hsts_missing"] == "fail"
    assert by_id["ocsp_unavailable"] == "warn"
    assert "hsts_short" not in by_id             # only when HSTS present


def test_build_checks_hsts_present_and_cert_ok():
    hsts = {"present": True, "max_age": 100000,
            "include_subdomains": True, "preload": False}
    cert = {"self_signed": False, "expired": False, "days_left": 200,
            "not_after": "Jan 01 00:00:00 2027 GMT"}
    versions = {"1.0": False, "1.1": False, "1.2": True, "1.3": True,
                "negotiated": None}
    ocsp = {"stapling": "yes", "responder": None}
    checks = network._build_ssl_checks(versions, [], hsts, ocsp, cert)
    by_id = {c["id"]: c["status"] for c in checks}
    assert by_id["hsts_missing"] == "pass"
    assert by_id["hsts_short"] == "fail"        # 100000 s < 180 days
    assert by_id["self_signed"] == "pass"
    assert by_id["cert_expired"] == "pass"
    assert by_id["cert_expiring"] == "pass"     # 200 days
    assert by_id["ocsp_unavailable"] == "pass"  # stapling yes


def test_build_checks_tls13_is_pfs_by_design():
    versions = {"1.0": False, "1.1": False, "1.2": True, "1.3": True,
                "negotiated": {"version": "TLSv1.3",
                              "cipher": "TLS_AES_256_GCM_SHA384"}}
    hsts = {"present": True, "max_age": 63072000,
            "include_subdomains": False, "preload": False}
    checks = network._build_ssl_checks(versions, [], hsts,
                                       {"stapling": "no", "responder": "x"}, None)
    by_id = {c["id"]: c["status"] for c in checks}
    assert by_id["no_forward_secrecy"] == "pass"


def test_build_checks_expiring_soon():
    cert = {"self_signed": False, "expired": False, "days_left": 12}
    hsts = {"present": True, "max_age": 63072000,
            "include_subdomains": False, "preload": False}
    versions = {"1.0": False, "1.1": False, "1.2": True, "1.3": True,
                "negotiated": None}
    checks = network._build_ssl_checks(versions, [], hsts,
                                       {"stapling": "no", "responder": "x"}, cert)
    by_id = {c["id"]: c["status"] for c in checks}
    assert by_id["cert_expiring"] == "warn"


# ── weak-cipher classification ─────────────────────────────────
def test_classify_weak_cipher_names():
    assert network._classify_weak_cipher("TLSv1.3 AES_256_GCM_SHA384") is None
    assert network._classify_weak_cipher("ECDHE-RSA-RC4-SHA") == "RC4"
    assert network._classify_weak_cipher("DES-CBC3-SHA") == "3DES"   # not single DES
    assert network._classify_weak_cipher("DES-EDE3-CBC-SHA") == "3DES"
    assert network._classify_weak_cipher("DES-CBC-SHA") == "DES"
    assert network._classify_weak_cipher("AES128-GCM-SHA256") is None
    assert network._classify_weak_cipher(None) is None


def test_probe_weak_ciphers_ignores_strong_negotiation(monkeypatch):
    # Server lands on a strong TLS 1.3 suite despite the weak offer:
    # nothing may be reported.
    def fake_handshake(host, port, ctx, timeout=8.0):
        return "TLSv1.3", "TLS_AES_256_GCM_SHA384"

    monkeypatch.setattr(network, "_tls_handshake", fake_handshake)
    assert network._probe_weak_ciphers("example.com", 443) == []


def test_probe_weak_ciphers_reports_real_rc4(monkeypatch):
    def fake_handshake(host, port, ctx, timeout=8.0):
        return "TLSv1", "ECDHE-RSA-RC4-SHA"

    monkeypatch.setattr(network, "_tls_handshake", fake_handshake)
    # The stub answers every family with the same RC4 name; whatever
    # families this OpenSSL can express, all hits must classify as RC4.
    res = network._probe_weak_ciphers("example.com", 443)
    assert res and set(res) == {"RC4"}


# ── OCSP raw probe: hello builder + record parser ───────────────
def _serverhello_record(extensions: bytes, session_id: bytes = b"") -> bytes:
    body = (b"\x03\x03" + b"R" * 32 + struct.pack("B", len(session_id))
            + session_id
            + struct.pack(">H", 2) + b"\x00\x9c"   # one cipher
            + b"\x01\x00"                          # comp methods
            + struct.pack(">H", len(extensions)) + extensions)
    hello = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return (b"\x16" + b"\x03\x03"
            + struct.pack(">H", len(hello)) + hello)


def _sni_ext(host: str) -> bytes:
    inner = struct.pack(">H", len(host)) + b"\x00" \
        + struct.pack(">H", len(host)) + host.encode()
    return struct.pack(">HH", 0, len(inner)) + inner


def test_client_hello_shape_and_extensions():
    data = network._build_ocsp_client_hello("example.com")
    assert data[0] == 0x16                       # handshake record
    assert struct.unpack(">H", data[3:5])[0] == len(data) - 5
    hello = data[5:]
    assert hello[0] == 0x01                     # ClientHello
    assert b"example.com" in hello              # SNI
    assert b"\x00\x05" in hello                 # status_request ext type 5


def test_parse_stapling_yes_no_and_incomplete():
    sni = _sni_ext("example.com")
    stapled = sni + struct.pack(">HH", 5, 3) + b"\x01\x02\x03"
    assert network._parse_stapling_from_records(
        _serverhello_record(stapled)) is True
    assert network._parse_stapling_from_records(
        _serverhello_record(sni)) is False
    # Truncated record: no conclusive answer yet.
    full = _serverhello_record(sni)
    assert network._parse_stapling_from_records(full[:len(full) - 5]) is None
    # Alert instead of ServerHello: unknown.
    alert = (b"\x16" + b"\x03\x03"
            + struct.pack(">H", 7) + b"\x15" + b"\x03\x03\x00\x02")
    assert network._parse_stapling_from_records(alert) is None


# ── handler (blocking pass stubbed) ─────────────────────────────
def _stub_scan(monkeypatch, result):
    calls = {}

    def fake(host, port):
        calls["args"] = (host, port)
        return result

    monkeypatch.setattr(network, "_ssl_deep_scan_blocking", fake)
    return calls


CLEAN_RESULT = {
    "target": "example.com",
    "port": 443,
    "tls_versions": {"1.0": False, "1.1": False, "1.2": True, "1.3": True},
    "negotiated": {"version": "TLSv1.3",
                   "cipher": "TLSv1.3 ECDHE-RSA-AES256-GCM-SHA384"},
    "weak_ciphers": [],
    "hsts": {"present": True, "max_age": 63072000,
             "include_subdomains": True, "preload": False},
    "ocsp": {"stapling": "yes", "responder": None},
    "cert": {"self_signed": False, "expired": False, "days_left": 100},
    "checks": [],
    "grade": "A+",
}


def test_handler_normalizes_target_and_delegates(monkeypatch):
    calls = _stub_scan(monkeypatch, CLEAN_RESULT)
    result = _run(network.ssl_deep_analyzer("https://Example.com:8443/whatever"))
    assert calls["args"] == ("example.com", 8443)
    assert result["grade"] == "A+"
    assert result["target"] == "example.com"


def test_handler_default_port(monkeypatch):
    calls = _stub_scan(monkeypatch, CLEAN_RESULT)
    _run(network.ssl_deep_analyzer("example.com"))
    assert calls["args"] == ("example.com", 443)


def test_handler_invalid_port_rejected(monkeypatch):
    def boom(host, port):
        raise AssertionError("must not probe")

    monkeypatch.setattr(network, "_ssl_deep_scan_blocking", boom)
    result = _run(network.ssl_deep_analyzer("example.com:abc"))
    assert "error" in result


def test_handler_no_tls_at_all_is_error(monkeypatch):
    dead = {
        "tls_versions": {"1.0": False, "1.1": False, "1.2": False, "1.3": False},
        "negotiated": None,
        "weak_ciphers": [],
        "hsts": {"present": False, "max_age": None,
                 "include_subdomains": False, "preload": False},
        "ocsp": {"stapling": "unknown", "responder": None},
        "cert": None,
        "checks": [],
        "grade": None,
    }
    _stub_scan(monkeypatch, dead)
    result = _run(network.ssl_deep_analyzer("example.com"))
    assert "error" in result and "No TLS handshake" in result["error"]


def test_handler_blocking_exception_captured(monkeypatch):
    def boom(host, port):
        raise RuntimeError("boom")

    monkeypatch.setattr(network, "_ssl_deep_scan_blocking", boom)
    result = _run(network.ssl_deep_analyzer("example.com"))
    assert "error" in result and "boom" in result["error"]


# ── findings adapter ────────────────────────────────────────────
def test_adapter_reports_failing_and_warn_checks():
    result = {
        "grade": "F",
        "checks": [
            {"id": "tls_legacy", "status": "fail", "detail": "Legacy: 1.0, 1.1"},
            {"id": "weak_cipher", "status": "fail", "detail": "RC4"},
            {"id": "no_forward_secrecy", "status": "pass", "detail": ""},
            {"id": "hsts_missing", "status": "fail", "detail": "absent"},
            {"id": "self_signed", "status": "warn", "detail": "unreadable"},
            {"id": "ocsp_unavailable", "status": "warn", "detail": "no ocsp"},
        ],
    }
    out = findings.extract_findings("ssl_deep_analyzer", result, "example.com")
    by_title_id = {f.evidence["check"]: f for f in out}
    assert len(out) == 4  # pass skipped; self_signed warn not mapped
    assert by_title_id["tls_legacy"].severity == findings.Severity.HIGH
    assert by_title_id["weak_cipher"].severity == findings.Severity.HIGH
    assert by_title_id["hsts_missing"].severity == findings.Severity.MEDIUM
    assert by_title_id["ocsp_unavailable"].severity == findings.Severity.LOW


def test_adapter_empty_result():
    assert findings.extract_findings("ssl_deep_analyzer", {}, "x") == []
    assert findings.extract_findings("ssl_deep_analyzer", {"checks": []}, "x") == []


# ── DER certificate fallback (getpeercert text form returns {}) ────
def _t(tag, content: bytes) -> bytes:
    if len(content) < 0x7F:
        return bytes([tag, len(content)]) + content
    lb = len(content).to_bytes(2, "big")
    return bytes([tag, 0x82]) + lb + content


def _name(cn: str) -> bytes:
    """X509Name DER: SEQUENCE of RDN SETs (one CN AVA here)."""
    val = _t(0x13, cn.encode())
    ava = _t(0x30, _t(0x06, b"\x55\x04\x03") + val)
    return _t(0x30, _t(0x31, ava))


def _synthetic_cert_der() -> bytes:
    issuer = _name("Example CA")
    subject = _name("example.com")
    validity = _t(0x30, _t(0x16, b"240101000000Z") + _t(0x16, b"270101000000Z"))
    tbs = (_t(0xA0, _t(0x02, b"\x02"))          # version v3
           + _t(0x02, b"\x01")                   # serial
           + _t(0x30, b"")                     # signature algorithm
           + issuer + validity + subject
           + _t(0x30, b""))                    # public key (empty)
    return _t(0x30, _t(0x30, tbs) + _t(0x03, b"\x00"))


def test_parse_name_cn_from_real_cloudflare_subject_bytes():
    subject = bytes.fromhex(
        "31 18 30 16 06 03 55 04 03 13 0f 73 61 6d 6d 69 64 65 62 6c 61 73 "
        "2e 63 6f 6d".replace(" ", ""))
    assert network._parse_name_cn(subject) == "sammideblas.com"


def test_parse_cert_der_synthetic():
    facts = network._parse_cert_der(_synthetic_cert_der())
    assert facts is not None
    assert facts["subject"] == "example.com"
    assert facts["issuer"] == "Example CA"
    assert facts["not_after"] == "270101000000Z"
    assert facts["san"] == []


def test_parse_cert_der_garbage_returns_none():
    assert network._parse_cert_der(b"\x01\x02\x03") is None
    assert network._parse_cert_der(None) is None


def test_cn_from_text_name_shape():
    name = (((("commonName", "github.com"),),))
    assert network._cn_from_text_name(name) == "github.com"
    assert network._cn_from_text_name(()) == ""
    assert network._cn_from_text_name(None) == ""


def test_cert_facts_text_form_path():
    text = {
        "subject": ((("commonName", "github.com"),),),
        "issuer": ((("commonName", "DigiCert"),),),
        "notAfter": "Sep 30 23:59:59 2026 GMT",
        "subjectAltName": [("DNS", "github.com")],
        "OCSP": ["http://ocsp.example"],
    }
    facts = network._cert_facts(text, None)
    assert facts["subject"] == "github.com"
    assert facts["issuer"] == "DigiCert"
    assert facts["san"] == ["github.com"]
    assert facts["ocsp_responder"] == "http://ocsp.example"
    assert facts["days_left"] is not None
    assert facts["expired"] is False
    assert facts["self_signed"] is False


def test_cert_facts_der_fallback_when_text_empty():
    facts = network._cert_facts({}, _synthetic_cert_der())
    assert facts["subject"] == "example.com"
    assert facts["issuer"] == "Example CA"
    assert facts["not_after"] == "270101000000Z"
    assert facts["days_left"] is not None
    assert facts["expired"] is False
    assert facts["self_signed"] is False


def test_cert_facts_self_signed_from_der():
    issuer = _name("example.com")
    subject = _name("example.com")
    validity = _t(0x30, _t(0x16, b"240101000000Z") + _t(0x16, b"270101000000Z"))
    tbs = (_t(0xA0, _t(0x02, b"\x02")) + _t(0x02, b"\x01") + _t(0x30, b"")
           + issuer + validity + subject + _t(0x30, b""))
    der = _t(0x30, _t(0x30, tbs) + _t(0x03, b"\x00"))
    facts = network._cert_facts({}, der)
    assert facts["self_signed"] is True


def test_parse_cert_der_extensions_san_and_aia():
    san_value = _t(0x30, _t(0x82, _t(0x16, b"alt.example.com")))
    san_ext = _t(0x30, _t(0x06, b"\x55\x1d\x11") + _t(0x04, san_value))
    aia_value = _t(0x30, _t(0x86, _t(0x16, b"http://ocsp.internals")))
    aia_ext = _t(0x30, _t(0x06, b"\x2b\x06\x01\x05\x05\x07\x30\x01") + _t(0x04, aia_value))
    issuer = _name("Example CA")
    subject = _name("example.com")
    validity = _t(0x30, _t(0x16, b"240101000000Z") + _t(0x16, b"270101000000Z"))
    tbs = (_t(0xA0, _t(0x02, b"\x02")) + _t(0x02, b"\x01") + _t(0x30, b"")
           + issuer + validity + subject + _t(0x30, b"")
           + _t(0xA3, _t(0x30, san_ext + aia_ext)))
    der = _t(0x30, _t(0x30, tbs) + _t(0x03, b"\x00"))
    facts = network._parse_cert_der(der)
    assert facts["san"] == ["alt.example.com"]
    assert facts["ocsp_responder"] == "http://ocsp.internals"
