"""F1-FAVICON: favicon fingerprinting por hash (recon pasivo puro).

Se descargan los paths de icono habituales del target, se computan MD5 y
SHA256 y se busca el hash contra la base local data/favicon_hashes.json
(favicons oficiales de stacks conocidos). Sin explotación activa: solo GETs.
"""
import asyncio
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

FAVICON_PATHS = ["/favicon.ico", "/favicon.png", "/icon.png", "/apple-touch-icon.png"]

# Base local de hashes (seed 2026-08-26: favicons oficiales de 6 stacks,
# fetch real; extensible editando data/favicon_hashes.json).
FAVICON_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "favicon_hashes.json"

_db_index: dict | None = None


def _load_db() -> dict:
    """Index por md5 y sha256 -> entrada. Cacheado a nivel de modulo."""
    global _db_index
    if _db_index is None:
        with open(FAVICON_DB_PATH) as f:
            entries = json.load(f)
        index: dict = {}
        for e in entries:
            index.setdefault(e["md5"], e)
            index.setdefault(e["sha256"], e)
        _db_index = index
    return _db_index


def _reset_db_cache():
    global _db_index
    _db_index = None


async def _favicon_fetch(url: str, session) -> tuple[int, str, bytes]:
    """GET pasivo de un icono. (status, content_type, bytes); fallo -> (0, '', b'')."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            data = await resp.read()
            return resp.status, resp.headers.get("Content-Type", ""), data or b""
    except Exception:
        return 0, "", b""


async def favicon_fingerprint(target: str, **kw) -> dict:
    """Hash MD5/SHA256 de los iconos del target y match contra la base local."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    p = urlparse(target)
    base = f"{p.scheme}://{p.netloc}"

    urls = [base + path for path in FAVICON_PATHS]
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30),
        connector=aiohttp.TCPConnector(ssl=False)
    ) as session:
        fetched = await asyncio.gather(*(_favicon_fetch(u, session) for u in urls))

    db = _load_db()
    icons: list[dict] = []
    matches: list[dict] = []
    for url, (status, ctype, data) in zip(urls, fetched):
        if status != 200 or not data:
            continue
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        icons.append({
            "url": url,
            "path": urlparse(url).path,
            "content_type": ctype,
            "bytes": len(data),
            "md5": md5,
            "sha256": sha256,
        })
        entry = db.get(md5) or db.get(sha256)
        if entry:
            matches.append({
                "stack": entry["name"],
                "path": urlparse(url).path,
                "md5": md5,
                "source": entry.get("source", ""),
            })

    return {
        "target": base,
        "icons": icons,
        "matches": matches,
        # Primera coincidencia: senal de instalacion por defecto / sin rebrandear.
        "stack": matches[0]["stack"] if matches else None,
    }
