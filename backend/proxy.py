"""Proxy configuration -- TOR and generic SOCKS5 support."""
import os
import socket
import asyncio
import shutil
from pathlib import Path

# Proxy state (set via API)
_proxy_config = {
    "enabled": False,
    "type": "none",       # "none", "tor", "socks5", "socks4"
    "host": "127.0.0.1",
    "port": 9150,         # TOR Browser default
    "username": "",
    "password": "",
}


def get_proxy_config() -> dict:
    return dict(_proxy_config)


def set_proxy_config(config: dict):
    global _proxy_config
    _proxy_config.update(config)


def get_aiohttp_connector():
    """Return an aiohttp connector with or without proxy."""
    if not _proxy_config["enabled"]:
        return None
    proxy_url = get_aiohttp_proxy()
    if not proxy_url:
        return None
    try:
        from aiohttp_socks import ProxyConnector
        return ProxyConnector.from_url(proxy_url, ssl=False)
    except ImportError:
        return None


def get_aiohttp_proxy() -> str | None:
    """Return proxy URL for aiohttp, or None if disabled."""
    if not _proxy_config["enabled"]:
        return None
    ptype = _proxy_config["type"]
    host = _proxy_config["host"]
    port = _proxy_config["port"]
    user = _proxy_config.get("username", "")
    pwd = _proxy_config.get("password", "")
    if ptype in ("tor", "socks5"):
        auth = f"{user}:{pwd}@" if user else ""
        return f"socks5://{auth}{host}:{port}"
    elif ptype == "socks4":
        return f"socks4://{host}:{port}"
    return None


def _find_tor_installation() -> dict:
    """Detect TOR Browser installation on the system (even if not running)."""
    import platform
    system = platform.system()

    if system == "Windows":
        # Common TOR Browser install locations on Windows
        check_paths = []
        # Desktop -- TOR Browser uses "Tor Browser/Browser/TorBrowser/Tor/tor.exe"
        desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
        check_paths.append(os.path.join(desktop, "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"))
        check_paths.append(os.path.join(desktop, "Tor Browser", "Browser", "tor.exe"))
        check_paths.append(os.path.join(desktop, "TorBrowser", "Browser", "TorBrowser", "Tor", "tor.exe"))
        check_paths.append(os.path.join(desktop, "TorBrowser", "Browser", "tor.exe"))
        # Program Files
        for pf in [os.environ.get("ProgramFiles", r"C:\Program Files"),
                    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]:
            check_paths.append(os.path.join(pf, "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"))
            check_paths.append(os.path.join(pf, "Tor Browser", "Browser", "tor.exe"))
        # Downloads
        downloads = os.path.join(os.environ.get("USERPROFILE", ""), "Downloads")
        check_paths.append(os.path.join(downloads, "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"))
        check_paths.append(os.path.join(downloads, "Tor Browser", "Browser", "tor.exe"))
        # LocalAppData
        localappdata = os.environ.get("LOCALAPPDATA", "")
        if localappdata:
            check_paths.append(os.path.join(localappdata, "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"))
            check_paths.append(os.path.join(localappdata, "Tor Browser", "Browser", "tor.exe"))
        # Expert bundle default
        for pf in [os.environ.get("ProgramFiles", r"C:\Program Files"),
                    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]:
            check_paths.append(os.path.join(pf, "Tor", "tor.exe"))

        for path in check_paths:
            if os.path.isfile(path):
                return {"installed": True, "path": path, "type": "tor_browser" if "Browser" in path else "expert_bundle"}

        # Check if tor.exe is in PATH
        tor_in_path = shutil.which("tor")
        if tor_in_path:
            return {"installed": True, "path": tor_in_path, "type": "system"}

    elif system == "Linux":
        # Check common Linux paths
        for path in ["/usr/bin/tor", "/usr/local/bin/tor", "/usr/sbin/tor"]:
            if os.path.isfile(path):
                return {"installed": True, "path": path, "type": "system"}
        tor_in_path = shutil.which("tor")
        if tor_in_path:
            return {"installed": True, "path": tor_in_path, "type": "system"}

    elif system == "Darwin":
        # macOS: /Applications/Tor Browser.app
        if os.path.isdir("/Applications/Tor Browser.app"):
            return {"installed": True, "path": "/Applications/Tor Browser.app", "type": "tor_browser"}
        tor_in_path = shutil.which("tor")
        if tor_in_path:
            return {"installed": True, "path": tor_in_path, "type": "system"}

    return {"installed": False, "path": None, "type": None}


def get_tor_status() -> dict:
    """Check if TOR is installed and/or running."""
    # First check if TOR is running (port check)
    running_port = None
    for port in [9150, 9050, 9151]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex(("127.0.0.1", port))
            s.close()
            if result == 0:
                running_port = port
                break
        except Exception:
            pass

    # Check if TOR is installed
    install_info = _find_tor_installation()

    if running_port:
        msg = f"TOR running on 127.0.0.1:{running_port}"
        if install_info["installed"]:
            msg += f" (installed at {install_info['path']})"
        return {
            "available": True,
            "running": True,
            "port": running_port,
            "installed": install_info["installed"],
            "install_path": install_info.get("path"),
            "install_type": install_info.get("type"),
            "message": msg,
        }
    elif install_info["installed"]:
        return {
            "available": False,
            "running": False,
            "port": 9150 if install_info["type"] == "tor_browser" else 9050,
            "installed": True,
            "install_path": install_info["path"],
            "install_type": install_info["type"],
            "message": f"TOR installed at {install_info['path']} but not running. Start {'TOR Browser' if install_info['type'] == 'tor_browser' else 'tor'} to use proxy.",
        }
    else:
        return {
            "available": False,
            "running": False,
            "port": 9050,
            "installed": False,
            "install_path": None,
            "install_type": None,
            "message": "TOR not detected. Install TOR Browser from https://www.torproject.org/download/",
        }


def get_tor_ip() -> str | None:
    """Get current TOR exit IP (async). Returns None if TOR not running."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex(("127.0.0.1", 9050))
        s.close()
        if result != 0:
            return None
        return "check via /api/proxy/tor-ip"
    except Exception:
        return None


# Proxychains-style env var for subprocess tools
def get_proxy_env() -> dict:
    """Return env vars to set proxy for subprocess-based tools."""
    if not _proxy_config["enabled"]:
        return {}
    proxy_url = get_aiohttp_proxy()
    if not proxy_url:
        return {}
    return {
        "HTTP_PROXY": proxy_url.replace("socks5://", "socks5h://"),
        "HTTPS_PROXY": proxy_url.replace("socks5://", "socks5h://"),
        "ALL_PROXY": proxy_url.replace("socks5://", "socks5h://"),
    }
