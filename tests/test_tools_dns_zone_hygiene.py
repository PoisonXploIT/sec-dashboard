"""F1-DNS: dns_zone_hygiene tool + findings adapter (no network)."""
import asyncio
import base64

import backend.findings as findings
import backend.tools.emailsec as emailsec


def _run(coro):
    return asyncio.run(coro)


# ── synthetic key material ─────────────────────────────────────
RSA_OID = bytes.fromhex("2a864886f70d010100")
ECDSA_OID = bytes.fromhex("2a8648ce3d030107")


def _tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    return bytes([tag, 0x82]) + len(content).to_bytes(2, "big") + content


def _spki(kind: str, key: bytes) -> str:
    """Build a minimal RFC 5280 SPKI (kind: 'rsa' | 'ec') and return it base64'd.

    RSA: BIT STRING = RSAPublicKey SEQUENCE { INTEGER modulus, INTEGER exp }
    (the real-world DKIM p= encoding; the parser must walk into the modulus).
    EC: BIT STRING = raw point.
    """
    if kind == "rsa":
        algid = _tlv(0x30, b"\x06\x09" + RSA_OID + b"\x05\x00")
        rsapubkey = _tlv(0x30, _tlv(0x02, b"\x00" + key) + _tlv(0x02, b"\x01\x00\x01"))
        bitstr = b"\x00" + rsapubkey
    else:
        algid = _tlv(0x30, b"\x06\x08" + ECDSA_OID)
        bitstr = b"\x00" + key
    return base64.b64encode(_tlv(0x30, algid + _tlv(0x03, bitstr))).decode()


def _mpi(nbits: int) -> bytes:
    """An n-bit RSA modulus as a base-128 MPI (leading byte keeps the width)."""
    return b"\xff" + b"\x00" * (nbits // 8 - 1)


EC_POINT = b"\x04" + b"\x11" * 32 + b"\x22" * 32

# ── _spki_key_bits ─────────────────────────────────────────────
def test_spki_rsa_bit_lengths():
    for nbits in (512, 1024, 2048):
        assert emailsec._spki_key_bits(_spki("rsa", _mpi(nbits))) == ("rsa", nbits)


def test_spki_ec_p256():
    assert emailsec._spki_key_bits(_spki("ec", EC_POINT)) == ("ec", 256)


def test_spki_unknown_and_garbage():
    assert emailsec._spki_key_bits("") == ("unknown", None)
    assert emailsec._spki_key_bits("!!!not-base64!!!") == ("unknown", None)
    assert emailsec._spki_key_bits(base64.b64encode(b"\x30\x30" * 5).decode()) == ("unknown", None)


# ── _dnskey_bits ────────────────────────────────────────────────
def test_dnskey_rsa_bits():
    b64 = base64.b64encode(_mpi(1024)).decode()
    assert emailsec._dnskey_bits(3, b64) == 1024
    assert emailsec._dnskey_bits(1, base64.b64encode(_mpi(512)).decode()) == 512


def test_dnskey_ec_and_unknown():
    assert emailsec._dnskey_bits(5, "") == 256          # ECDSAP256
    assert emailsec._dnskey_bits(13, "AAAA") is None   # Ed25519: not derivable
    assert emailsec._dnskey_bits(3, "!!!") is None     # bad base64


# ── _spf_summary / _dmarc_issues / _dkim_parse ─────────────────
def test_spf_summary_policies():
    assert emailsec._spf_summary("v=spf1 +all") == {"permissive": True, "hardfail": False, "mechanism_count": 1}
    assert emailsec._spf_summary("v=spf1 -all") == {"permissive": False, "hardfail": True, "mechanism_count": 1}
    assert emailsec._spf_summary("v=spf1 ~all")["permissive"] is False
    assert emailsec._spf_summary("v=spf1 ?all")["hardfail"] is False
    s = emailsec._spf_summary("v=spf1 ip4:192.0.2.0/24 include:x.example.com -all")
    assert s == {"permissive": False, "hardfail": True, "mechanism_count": 3}


def test_dmarc_issues():
    assert emailsec._dmarc_issues("v=DMARC1; p=none") == ["dmarc_p_none"]
    assert emailsec._dmarc_issues("v=DMARC1; p=reject; pct=50") == ["dmarc_pct_partial"]
    assert emailsec._dmarc_issues("v=DMARC1; p=reject; sp=none") == ["dmarc_sp_weak"]
    assert emailsec._dmarc_issues("v=DMARC1; p=quarantine; sp=quarantine") == []
    assert emailsec._dmarc_issues("v=DMARC1; p=reject; pct=100; sp=reject") == []


def test_dkim_parse():
    assert emailsec._dkim_parse("v=DKIM1; k=rsa; t=y; p=AAAA") == {"empty_key": False, "key_b64": "AAAA"}
    assert emailsec._dkim_parse("v=DKIM1; p=") == {"empty_key": True, "key_b64": ""}
    assert emailsec._dkim_parse("v=DKIM1; k=rsa")["empty_key"] is True


# ── handler (stubbed DNS) ───────────────────────────────────────
def _stub_dns(monkeypatch, txt_map=None, default=("noanswer", []), dnskey=("noanswer", [])):
    async def fake_txt(name, lifetime=8.0):
        return (txt_map or {}).get(name, default)

    async def fake_dnskey(domain, lifetime=8.0):
        return dnskey

    monkeypatch.setattr(emailsec, "_hygiene_txt", fake_txt)
    monkeypatch.setattr(emailsec, "_hygiene_dnskey", fake_dnskey)


def test_handler_bad_zone_full_of_issues(monkeypatch):
    _stub_dns(
        monkeypatch,
        txt_map={
            "example.com": ("ok", ["v=spf1 +all"]),
            "_dmarc.example.com": ("noanswer", []),
        },
        dnskey=("ok", [{"algorithm": 3, "flags": 256,
                        "publickey": base64.b64encode(_mpi(512)).decode()}]),
    )
    result = _run(emailsec.dns_zone_hygiene("example.com"))
    ids = [i["id"] for i in result["issues"]]
    assert set(ids) == {"spf_permissive_all", "dmarc_missing", "dkim_missing", "dnskey_weak"}
    assert result["count"] == 4
    assert result["dkim"]["found"] == []
    assert result["dnskey"]["keys"][0]["key_bits"] == 512


def test_handler_clean_zone_no_issues(monkeypatch):
    dkim_2048 = _spki("rsa", _mpi(2048))
    _stub_dns(
        monkeypatch,
        txt_map={
            "example.com": ("ok", ["v=spf1 ip4:192.0.2.0/24 -all"]),
            "_dmarc.example.com": ("ok", ["v=DMARC1; p=reject; sp=reject"]),
            "s1._domainkey.example.com": ("ok", [f"v=DKIM1; k=rsa; p={dkim_2048}"]),
        },
        dnskey=("ok", [{"algorithm": 3, "flags": 257,
                        "publickey": base64.b64encode(_mpi(2048)).decode()}]),
    )
    result = _run(emailsec.dns_zone_hygiene("example.com"))
    assert result["issues"] == []
    assert result["count"] == 0
    assert result["dkim"]["found"][0]["key_bits"] == 2048
    assert result["spf"]["terminal_hardfail"] is True


def test_handler_dkim_empty_and_weak_keys(monkeypatch):
    weak = _spki("rsa", _mpi(512))
    _stub_dns(
        monkeypatch,
        txt_map={
            "example.com": ("ok", []),
            "_dmarc.example.com": ("ok", ["v=DMARC1; p=none"]),
            "default._domainkey.example.com": ("ok", ["v=DKIM1; p="]),
            "s1._domainkey.example.com": ("ok", [f"v=DKIM1; k=rsa; p={weak}"]),
        },
    )
    result = _run(emailsec.dns_zone_hygiene("example.com"))
    ids = sorted(i["id"] for i in result["issues"])
    assert ids == ["dkim_empty_key", "dkim_key_weak", "dmarc_p_none", "spf_missing"]
    assert result["dkim"]["count"] == 2


def test_handler_nxdomain_apex_is_clean_error(monkeypatch):
    _stub_dns(monkeypatch, txt_map={"example.com": ("nxdomain", [])})
    result = _run(emailsec.dns_zone_hygiene("example.com"))
    assert "error" in result


def test_handler_rejects_ip_target():
    result = _run(emailsec.dns_zone_hygiene("10.0.0.5"))
    assert "error" in result


def test_handler_all_errors_emit_no_missing_conclusions(monkeypatch):
    _stub_dns(
        monkeypatch,
        txt_map={"example.com": ("error", [])},
        default=("error", []),
        dnskey=("error", []),
    )
    result = _run(emailsec.dns_zone_hygiene("example.com"))
    assert result["issues"] == []
    assert result["spf"]["status"] == "error"
    assert result["dmarc"]["status"] == "error"
    assert result["dnskey"]["status"] == "error"
    assert result["dkim"]["count"] == 0


# ── findings adapter ───────────────────────────────────────────
def test_adapter_severities_and_dedup():
    result = {"issues": [
        {"id": "spf_permissive_all", "detail": "x"},
        {"id": "spf_permissive_all", "detail": "x"},  # duplicate
        {"id": "dmarc_p_none", "detail": "y"},
        {"id": "dkim_key_weak", "detail": "z"},
        {"id": "spf_no_hardfail", "detail": "w"},
        {"id": "dnskey_legacy", "detail": "v"},
    ]}
    out = findings.extract_findings("dns_zone_hygiene", result, "example.com")
    assert len(out) == 5  # duplicate dropped
    by_check = {f.evidence["check"]: f.severity for f in out}
    assert by_check["spf_permissive_all"] == findings.Severity.HIGH
    assert by_check["dmarc_p_none"] == findings.Severity.MEDIUM
    assert by_check["dkim_key_weak"] == findings.Severity.HIGH
    assert by_check["spf_no_hardfail"] == findings.Severity.LOW
    assert by_check["dnskey_legacy"] == findings.Severity.LOW


def test_adapter_empty_and_unknown_ids():
    assert findings.extract_findings("dns_zone_hygiene", {}, "x") == []
    out = findings.extract_findings(
        "dns_zone_hygiene", {"issues": [{"id": "not_a_real_check", "detail": ""}]}, "x")
    assert out == []
