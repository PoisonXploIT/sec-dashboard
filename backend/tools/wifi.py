"""WiFi hardware tools — poll Flask dashboards from M5Stick devices.

These tools connect to external Flask apps that capture serial data from
M5Stick hardware (Marauder / Evil-M5Project firmware) and expose JSON APIs.

Requirements:
- wifi-marauder-viewer running (default: http://127.0.0.1:5000)
  Repo: https://github.com/PoisonXploIT/wifi-marauder-viewer
- Visualizacion_extendida_M5StickPlus2 running (default: http://127.0.0.1:5000)
  Repo: https://github.com/PoisonXploIT/Visualizacion_extendida_M5StickPlus2

The 'target' parameter is the base URL of the Flask app (e.g. http://127.0.0.1:5000).
If empty, defaults to http://127.0.0.1:5000.
"""
import asyncio
from datetime import datetime

import aiohttp


async def _fetch_json(url: str, timeout: int = 15) -> dict:
    """Fetch JSON from a URL and return the parsed dict."""
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=timeout)
    ) as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status} from {url}")
            return await resp.json()


# ── WiFi Marauder Scan (M5StickC + Marauder firmware) ──────────

async def wifi_marauder_scan(target: str = "", **kw) -> dict:
    """Poll WiFi scan data from wifi-marauder-viewer Flask app.

    Fetches /api/scan.json from the viewer and returns the parsed JSON.
    The viewer parses PuTTY serial logs from M5StickC Marauder firmware
    and deduplicates networks by BSSID.

    Returns:
        {
          "scan_time": "...",
          "total_networks": N,
          "networks": [{channel, rssi, bssid, essid, first_seen, last_seen}, ...]
        }
    """
    base_url = (target or "http://127.0.0.1:5000").rstrip("/")
    api_url = f"{base_url}/api/scan.json"

    try:
        data = await _fetch_json(api_url, timeout=15)
    except aiohttp.ClientConnectorError as e:
        return {
            "error": f"Cannot connect to {base_url}. Is wifi-marauder-viewer running?",
            "hint": "git clone https://github.com/PoisonXploIT/wifi-marauder-viewer && python app.py",
            "url": api_url,
            "detail": str(e)[:200],
        }
    except Exception as e:
        return {
            "error": f"Failed to fetch scan data: {e}",
            "url": api_url,
        }

    networks = data.get("networks", [])
    rssi_values = [n.get("rssi", 0) for n in networks if isinstance(n.get("rssi"), (int, float))]

    return {
        "source": "wifi-marauder-viewer",
        "url": api_url,
        "scan_time": data.get("scan_time", datetime.utcnow().isoformat()),
        "total_networks": data.get("total_networks", len(networks)),
        "networks": networks,
        "summary": {
            "avg_rssi": round(sum(rssi_values) / len(rssi_values), 1) if rssi_values else None,
            "best_rssi": max(rssi_values) if rssi_values else None,
            "worst_rssi": min(rssi_values) if rssi_values else None,
            "channels": sorted(set(n.get("channel") for n in networks if n.get("channel"))),
        },
    }


# ── M5Stick Plus 2 Networks (Evil-M5Project firmware) ──────────

async def m5stick_networks(target: str = "", **kw) -> dict:
    """Poll WiFi networks + clients from M5Stick Plus 2 viewer Flask app.

    Fetches /api/networks.json from the viewer and returns the parsed JSON.
    The viewer reads serial data from M5Stick Plus 2 with Evil-M5Project firmware.

    Returns:
        {
          "scan_time": "...",
          "total_networks": N,
          "total_clients": M,
          "networks": [{ssid, bssid, channel, n_clients, last_seen}, ...]
        }
    """
    base_url = (target or "http://127.0.0.1:5000").rstrip("/")
    api_url = f"{base_url}/api/networks.json"

    try:
        data = await _fetch_json(api_url, timeout=15)
    except aiohttp.ClientConnectorError as e:
        return {
            "error": f"Cannot connect to {base_url}. Is the M5Stick Plus 2 viewer running?",
            "hint": "git clone https://github.com/PoisonXploIT/Visualizacion_extendida_M5StickPlus2 && python src/app.py",
            "url": api_url,
            "detail": str(e)[:200],
        }
    except Exception as e:
        return {
            "error": f"Failed to fetch networks data: {e}",
            "url": api_url,
        }

    networks = data.get("networks", [])
    total_clients = sum(n.get("n_clients", 0) for n in networks if isinstance(n.get("n_clients"), int))

    return {
        "source": "m5stick-plus2-viewer",
        "url": api_url,
        "scan_time": data.get("scan_time", datetime.utcnow().isoformat()),
        "total_networks": data.get("total_networks", len(networks)),
        "total_clients": data.get("total_clients", total_clients),
        "networks": networks,
        "summary": {
            "networks_with_clients": sum(1 for n in networks if n.get("n_clients", 0) > 0),
            "total_clients": total_clients,
            "channels": sorted(set(n.get("channel") for n in networks if n.get("channel"))),
        },
    }
