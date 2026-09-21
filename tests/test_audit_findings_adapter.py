"""ps_security_audit findings adapter (AMENAZAS_DETECTADAS.json -> findings).

No network, no PowerShell: a fake Auditoria_<ts> folder in tmp_path with the
threat JSON the script exports. Verifies the mapping that makes the AI layer
(Jev verdicts + local LLM explanations) apply to enterprise audits.
"""
import json

from backend.findings import extract_findings


def _write_threats(folder, data):
    (folder / "AMENAZAS_DETECTADAS.json").write_text(
        json.dumps(data), encoding="utf-8")


def test_threats_map_to_normalized_findings(tmp_path):
    folder = tmp_path / "Auditoria_20260921"
    folder.mkdir()
    _write_threats(folder, [
        {
            "Timestamp": "2026-09-21 10:00:00",
            "ThreatType": "Proceso sin ruta",
            "Severity": "HIGH",
            "Description": "El proceso C:\\x.exe no tiene ruta valida.",
            "Details": {"ProcessName": "x.exe", "PID": 42},
        },
        {
            "Timestamp": "2026-09-21 10:00:01",
            "ThreatType": "Usuario sin contrasena",
            "Severity": "CRITICAL",
            "Description": "El usuario admin no requiere contrasena.",
            "Details": {"User": "admin"},
        },
    ])
    findings = extract_findings(
        "ps_security_audit",
        {"output_folder": str(folder), "modules_found": 10},
        "localhost",
    )
    assert len(findings) == 2
    f0, f1 = findings
    assert f0.severity.value == "high" and f1.severity.value == "critical"
    assert f0.title == "Proceso sin ruta"
    assert f0.description.startswith("El proceso")
    assert f0.evidence == {"ProcessName": "x.exe", "PID": 42}
    assert f0.tool == "ps_security_audit"
    assert f0.category == "Enterprise Audit"
    assert f0.target == "localhost"
    # Stable identity: same inputs hash to the same finding_id.
    again = extract_findings(
        "ps_security_audit", {"output_folder": str(folder)}, "localhost")
    assert again[0].finding_id == f0.finding_id


def test_single_threat_serialized_as_object(tmp_path):
    # PowerShell 5.1 ConvertTo-Json: one threat -> JSON object, not array.
    folder = tmp_path / "Auditoria_20260921"
    folder.mkdir()
    _write_threats(folder, {
        "Timestamp": "2026-09-21 10:00:00",
        "ThreatType": "Comando codificado",
        "Severity": "CRITICAL",
        "Description": "powershell -enc detectado.",
        "Details": {"CommandLine": "-enc JAB..."},
    })
    findings = extract_findings(
        "ps_security_audit", {"output_folder": str(folder)}, "localhost")
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert findings[0].title == "Comando codificado"


def test_no_threats_file_gives_info_finding(tmp_path):
    folder = tmp_path / "Auditoria_20260921"
    folder.mkdir()  # no AMENAZAS_DETECTADAS.json (clean audit)
    findings = extract_findings(
        "ps_security_audit",
        {"output_folder": str(folder), "modules_found": 10},
        "localhost",
    )
    assert len(findings) == 1
    assert findings[0].severity.value == "info"
    assert "sin amenazas" in findings[0].title


def test_error_result_gives_no_findings():
    assert extract_findings(
        "ps_security_audit", {"error": "Audit timed out"}, "localhost") == []


def test_missing_output_folder_falls_back(tmp_path):
    findings = extract_findings(
        "ps_security_audit", {"status": "completed"}, "localhost")
    assert len(findings) == 1
    assert findings[0].severity.value == "info"


def test_unknown_severity_defaults_to_medium(tmp_path):
    folder = tmp_path / "Auditoria_20260921"
    folder.mkdir()
    _write_threats(folder, [
        {"Timestamp": "t", "ThreatType": "X", "Severity": "WEIRD",
         "Description": "d", "Details": None},
    ])
    findings = extract_findings(
        "ps_security_audit", {"output_folder": str(folder)}, "localhost")
    assert findings[0].severity.value == "medium"


def test_findings_capped_at_100(tmp_path):
    folder = tmp_path / "Auditoria_20260921"
    folder.mkdir()
    _write_threats(folder, [
        {"Timestamp": f"t{i}", "ThreatType": f"T{i}", "Severity": "LOW",
         "Description": "d", "Details": None}
        for i in range(150)
    ])
    findings = extract_findings(
        "ps_security_audit", {"output_folder": str(folder)}, "localhost")
    assert len(findings) == 100
