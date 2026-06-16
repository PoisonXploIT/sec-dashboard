"""System tools — Windows-compatible, no admin required."""
import asyncio
import json
import os
import platform
import socket
import subprocess
from datetime import datetime


async def _run_cmd(cmd: list[str], timeout: int = 15) -> str:
    """Run a command and return stdout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"Error: {e}"


# ── 20. Network Connections ────────────────────────────────────
async def network_connections(**kw) -> dict:
    """Active network connections and listening ports."""
    output = await _run_cmd(["netstat", "-ano"])

    connections = []
    listening = []
    established = []

    for line in output.split("\n"):
        line = line.strip()
        if not line or line.startswith("Proto") or line.startswith("Active"):
            continue

        parts = line.split()
        if len(parts) >= 4:
            proto = parts[0]
            local = parts[1]
            foreign = parts[2] if len(parts) > 2 else ""
            state = parts[3] if len(parts) > 3 else ""
            pid = parts[4] if len(parts) > 4 else ""

            entry = {
                "protocol": proto,
                "local_address": local,
                "foreign_address": foreign,
                "state": state,
                "pid": int(pid) if pid.isdigit() else pid,
            }

            connections.append(entry)
            if state == "LISTENING":
                listening.append(entry)
            elif state == "ESTABLISHED":
                established.append(entry)

    return {
        "total_connections": len(connections),
        "listening": len(listening),
        "established": len(established),
        "listening_ports": listening[:30],
        "established_connections": established[:20],
    }


# ── 21. Process Monitor ────────────────────────────────────────
async def process_monitor(**kw) -> dict:
    """Running process analysis with network correlation."""
    output = await _run_cmd(["tasklist", "/FO", "CSV", "/NH"])

    processes = []
    for line in output.split("\n"):
        line = line.strip().strip('"')
        if not line:
            continue
        parts = line.split('","')
        if len(parts) >= 5:
            name = parts[0].strip('"')
            pid = parts[1].strip('"')
            session = parts[2].strip('"')
            mem = parts[4].strip('"').replace(",", "").replace(" K", "")

            if name == "Image Name":
                continue

            processes.append({
                "name": name,
                "pid": pid,
                "session": session,
                "memory_kb": int(mem) if mem.isdigit() else 0,
            })

    # Sort by memory
    processes.sort(key=lambda x: x.get("memory_kb", 0), reverse=True)

    # Get listening port PIDs
    netstat_out = await _run_cmd(["netstat", "-ano"])
    pid_ports = {}
    for line in netstat_out.split("\n"):
        parts = line.strip().split()
        if len(parts) >= 5 and parts[3] == "LISTENING":
            pid = parts[4]
            addr = parts[1]
            if pid not in pid_ports:
                pid_ports[pid] = []
            pid_ports[pid].append(addr)

    # Enrich processes with port info
    for proc in processes[:30]:
        pid = proc["pid"]
        if pid in pid_ports:
            proc["listening_ports"] = pid_ports[pid]

    return {
        "total_processes": len(processes),
        "top_by_memory": processes[:20],
        "processes_with_ports": [
            p for p in processes if "listening_ports" in p
        ],
    }


# ── 22. System Info ────────────────────────────────────────────
async def system_info(**kw) -> dict:
    """OS, network interfaces, firewall, and security posture."""
    info = {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "hostname": socket.gethostname(),
        },
        "network": {},
        "security": {},
    }

    # Network interfaces (from ipconfig)
    ipconfig = await _run_cmd(["ipconfig", "/all"])
    interfaces = []
    current = {}
    for line in ipconfig.split("\n"):
        line = line.strip()
        if not line:
            if current:
                interfaces.append(current)
                current = {}
            continue
        if ":" in line and not line.startswith(" "):
            if "adapter" in line.lower():
                if current:
                    interfaces.append(current)
                current = {"name": line.rstrip(":"), "details": []}
            elif current:
                current["details"].append(line)
        elif current:
            current["details"].append(line)
    if current:
        interfaces.append(current)
    info["network"]["interfaces"] = interfaces[:10]

    # Local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["network"]["local_ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        info["network"]["local_ip"] = "unknown"

    # Public IP
    try:
        async with __import__("aiohttp").ClientSession(
            timeout=__import__("aiohttp").ClientTimeout(total=5)
        ) as session:
            async with session.get("https://api.ipify.org?format=json") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    info["network"]["public_ip"] = data.get("ip")
    except Exception:
        info["network"]["public_ip"] = "unavailable"

    # Firewall status
    firewall = await _run_cmd(["netsh", "advfirewall", "show", "currentprofile"])
    info["security"]["firewall"] = "ON" if "ON" in firewall.upper() else "OFF" if "OFF" in firewall.upper() else "unknown"

    # Windows Defender status
    defender = await _run_cmd([
        "powershell", "-Command",
        "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json"
    ])
    try:
        def_status = json.loads(defender.strip())
        info["security"]["defender_enabled"] = def_status.get("AntivirusEnabled")
        info["security"]["realtime_protection"] = def_status.get("RealTimeProtectionEnabled")
    except (json.JSONDecodeError, Exception):
        info["security"]["defender_enabled"] = "unknown"

    # UAC status
    uac = await _run_cmd([
        "reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "EnableLUA"
    ])
    info["security"]["uac"] = "Enabled" if "0x1" in uac else "Disabled" if "0x0" in uac else "unknown"

    # Disk usage
    try:
        import shutil
        total, used, free = shutil.disk_usage("C:\\")
        info["disk"] = {
            "total_gb": round(total / (1024**3), 1),
            "used_gb": round(used / (1024**3), 1),
            "free_gb": round(free / (1024**3), 1),
            "usage_percent": round(used / total * 100, 1),
        }
    except Exception:
        pass

    # RAM
    try:
        import psutil
        mem = psutil.virtual_memory()
        info["memory"] = {
            "total_gb": round(mem.total / (1024**3), 1),
            "available_gb": round(mem.available / (1024**3), 1),
            "usage_percent": mem.percent,
        }
    except ImportError:
        ps_out = await _run_cmd([
            "powershell", "-Command",
            "(Get-CimInstance Win32_OperatingSystem | Select @{N='TotalGB';E={[math]::Round($_.TotalVisibleMemorySize/1MB,1)}}, @{N='FreeGB';E={[math]::Round($_.FreePhysicalMemory/1MB,1)}}) | ConvertTo-Json"
        ])
        try:
            ps_mem = json.loads(ps_out.strip())
            info["memory"] = {
                "total_gb": ps_mem.get("TotalGB"),
                "available_gb": ps_mem.get("FreeGB"),
            }
        except Exception:
            pass

    return info
