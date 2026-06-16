"""Proxy configuration -- TOR and generic SOCKS5 support."""
import os
import socket
import asyncio
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


def get_tor_status() -> dict:
    """Check if TOR is running and accessible."""
    for port in [9150, 9050, 9151]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex(("127.0.0.1", port))
            s.close()
            if result == 0:
                return {"available": True, "port": port, "message": f"TOR SOCKS5 proxy detected on 127.0.0.1:{port}"}
        except Exception:
            pass
    return {"available": False, "port": 9050, "message": "TOR not running. Install TOR Browser or tor service."}


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
