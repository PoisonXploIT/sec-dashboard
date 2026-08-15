"""Target validation -- SSRF protection for remote deployments."""
import ipaddress
import os
import socket
from pathlib import Path


def is_remote_mode() -> bool:
    """True if SSRF protection is enforced.

    Auto-detect: if PORT env var is set (Railway), enforce validation.
    Evaluated at call time so the env var can change at runtime.
    """
    if os.environ.get("SEC_DASHBOARD_REMOTE", "").lower() in ("1", "true", "yes"):
        return True
    return bool(os.environ.get("PORT"))


def validate_target(host: str) -> tuple[bool, str]:
    """Validate a target host. Returns (is_valid, reason).

    In remote mode, blocks private/loopback/link-local/metadata IPs.
    In local mode, allows everything.
    """
    if not host or not host.strip():
        return False, "Host cannot be empty"

    host = host.strip()

    # Check for AWS/GCP/Azure metadata endpoints
    metadata_hosts = {"169.254.169.254", "metadata.google.internal", "metadata"}
    if host.lower() in metadata_hosts:
        if is_remote_mode():
            return False, "Metadata endpoint blocked (SSRF protection)"
        return True, "Metadata endpoint (allowed in local mode)"

    # Try to parse as IP
    try:
        ip = ipaddress.ip_address(host)
        if is_remote_mode():
            if ip.is_private:
                return False, f"Private IP blocked (SSRF protection): {host}"
            if ip.is_loopback:
                return False, f"Loopback IP blocked (SSRF protection): {host}"
            if ip.is_link_local:
                return False, f"Link-local IP blocked (SSRF protection): {host}"
            if ip.is_reserved:
                return False, f"Reserved IP blocked (SSRF protection): {host}"
        return True, "Valid IP address"
    except ValueError:
        pass  # Not an IP, check as hostname

    # Check for localhost variants
    localhost_names = {"localhost", "localhost.localdomain", "0.0.0.0"}
    if host.lower() in localhost_names:
        if is_remote_mode():
            return False, f"Localhost blocked (SSRF protection): {host}"
        return True, "Localhost (allowed in local mode)"

    # Check for internal hostnames (.internal, .local, .corp, etc.)
    internal_tlds = [".internal", ".local", ".corp", ".lan", ".intranet"]
    for tld in internal_tlds:
        if host.lower().endswith(tld):
            if is_remote_mode():
                return False, f"Internal hostname blocked (SSRF protection): {host}"
            return True, f"Internal hostname (allowed in local mode)"

    # Try DNS resolution to check if it resolves to private IP
    if is_remote_mode():
        try:
            resolved = socket.getaddrinfo(host, None)
            for family, _, _, _, sockaddr in resolved:
                ip_str = sockaddr[0]
                try:
                    resolved_ip = ipaddress.ip_address(ip_str)
                    if resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_link_local:
                        return False, f"Host resolves to private IP (SSRF protection): {host} -> {ip_str}"
                except ValueError:
                    continue
        except socket.gaierror:
            # Can't resolve -- allow it, the tool will fail naturally
            pass

    return True, "Valid hostname"
