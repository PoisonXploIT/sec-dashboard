"""PowerShell Security Audit tool — wraps Auditing_with_PowerShell script.

Requires the Auditing_with_PowerShell repo cloned on this machine.
Set env var AUDIT_PS_PATH to the repo root (where Invoke-SecurityAudit.ps1 lives).
Only works on Windows. On other OS, returns a clear error.
"""
import asyncio
import json
import os
import platform
from pathlib import Path


def _find_script() -> str | None:
    """Locate Invoke-SecurityAudit.ps1 on disk."""
    # 1. Explicit env var
    env_path = os.environ.get("AUDIT_PS_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file() and p.name == "Invoke-SecurityAudit.ps1":
            return str(p)
        if p.is_dir():
            candidate = p / "Invoke-SecurityAudit.ps1"
            if candidate.exists():
                return str(candidate)

    # 2. Common locations relative to sec-dashboard
    candidates = [
        Path(__file__).resolve().parent.parent.parent / "Auditing_with_PowerShell" / "Invoke-SecurityAudit.ps1",
        Path(__file__).resolve().parent.parent.parent.parent / "Auditing_with_PowerShell" / "Invoke-SecurityAudit.ps1",
        Path.home() / "Auditing_with_PowerShell" / "Invoke-SecurityAudit.ps1",
        Path.home() / "Desktop" / "Auditing_with_PowerShell" / "Invoke-SecurityAudit.ps1",
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    return None


def _find_wrapper() -> str | None:
    """Locate run-audit.ps1 (AMSI bypass wrapper) on disk."""
    script_path = _find_script()
    if script_path:
        wrapper = Path(script_path).parent / "run-audit.ps1"
        if wrapper.exists():
            return str(wrapper)
    return None


async def ps_security_audit(**kw) -> dict:
    """Run the PowerShell security audit script and return a summary.

    This tool executes the external Auditing_with_PowerShell script
    (https://github.com/PoisonXploIT/Auditing_with_PowerShell) which performs
    a 10-module enterprise security audit: system info, users, processes,
    network, logs, files, registry, services, LOLBAS, and drivers.

    The script generates JSON/CSV/TXT output in a timestamped folder.
    This wrapper runs the script, then reads the generated JSON files and
    returns a structured summary.

    Requirements:
    - Windows only (PowerShell 5.1+)
    - Auditing_with_PowerShell repo cloned locally
    - Admin privileges recommended for full audit
    """
    if platform.system() != "Windows":
        return {
            "error": "PowerShell Security Audit only runs on Windows",
            "platform": platform.system(),
        }

    script_path = _find_script()
    if not script_path:
        return {
            "error": "Invoke-SecurityAudit.ps1 not found",
            "hint": "Clone https://github.com/PoisonXploIT/Auditing_with_PowerShell and set AUDIT_PS_PATH env var to the repo root",
        }

    # Run the script with -NoProfile and bypass execution policy
    # The script creates Auditoria_<timestamp>/ with 10 subfolders of JSON/CSV/TXT
    # Use run-audit.ps1 wrapper if available (bypasses AMSI false positive blocking)
    run_script = _find_wrapper() or script_path
    cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", run_script,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(Path(script_path).parent),
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        return {
            "error": "Audit timed out after 600s",
            "script": script_path,
        }
    except Exception as e:
        return {
            "error": f"Failed to execute script: {e}",
            "script": script_path,
        }

    # Find the output folder (Auditoria_<timestamp>)
    script_dir = Path(script_path).parent
    audit_folders = sorted(
        [d for d in script_dir.iterdir() if d.is_dir() and d.name.startswith("Auditoria_")],
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )

    if not audit_folders:
        return {
            "error": "Script completed but no output folder found",
            "stdout": stdout_text[-500:],
            "stderr": stderr_text[-500:],
            "script": script_path,
        }

    audit_folder = audit_folders[0]

    # Collect all JSON results from subfolders
    results = {}
    module_summaries = []

    for subdir in sorted(audit_folder.iterdir()):
        if not subdir.is_dir():
            continue
        json_files = list(subdir.glob("*.json"))
        for jf in json_files:
            try:
                data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
                module_name = subdir.name
                # If data is a list, count items; if dict, extract keys
                if isinstance(data, list):
                    count = len(data)
                    module_summaries.append({
                        "module": module_name,
                        "file": jf.name,
                        "type": "list",
                        "items": count,
                    })
                    results[f"{module_name}/{jf.stem}"] = data[:50]  # cap at 50 items
                elif isinstance(data, dict):
                    module_summaries.append({
                        "module": module_name,
                        "file": jf.name,
                        "type": "dict",
                        "keys": list(data.keys())[:10],
                    })
                    results[f"{module_name}/{jf.stem}"] = data
            except (json.JSONDecodeError, Exception):
                pass

    # Read the audit log if present
    log_file = audit_folder / "auditoria.log"
    log_text = ""
    if log_file.exists():
        log_text = log_file.read_text(encoding="utf-8", errors="replace")[:2000]

    return {
        "status": "completed",
        "script": script_path,
        "output_folder": str(audit_folder),
        "modules_found": len(module_summaries),
        "module_summaries": module_summaries,
        "results": results,
        "audit_log": log_text,
        "stdout_tail": stdout_text[-300:] if stdout_text else "",
        "stderr_tail": stderr_text[-300:] if stderr_text else "",
        "return_code": proc.returncode,
    }