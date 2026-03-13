"""SSRF private IP detector — flags URLs and bare IPs targeting private/internal addresses."""

from __future__ import annotations

import ipaddress
import re
import urllib.parse

from agentgate.detectors._util import extract_strings
from agentgate.models import DetectorResult, ToolCall

# Conservative bare-IP regexes (avoid false positives on non-IP strings)
_BARE_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_BARE_IPV6_RE = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")


def _extract_host_from_url(value: str) -> str | None:
    """Extract hostname from a URL string, stripping IPv6 brackets.

    Returns None if the string is not a URL or has no hostname.
    """
    parsed = urllib.parse.urlparse(value)
    if not parsed.scheme or not parsed.hostname:
        return None
    return parsed.hostname


def _is_dangerous_ip(host: str) -> bool:
    """Check if a host string is a private/loopback/link-local/reserved IP.

    Returns False if the string is not a valid IP address (e.g., a hostname).
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    # Explicit checks for Python 3.10 compat (is_private behavior varies)
    if ip == ipaddress.ip_address("0.0.0.0") or ip == ipaddress.ip_address("::"):
        return True

    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def detect(tool_call: ToolCall) -> DetectorResult:
    """Scan all string parameter values for SSRF-dangerous IP addresses.

    Returns DetectorResult with matched=True on first private/loopback/
    link-local/metadata IP found in any URL or bare IP string.
    """
    strings = extract_strings(tool_call.arguments)

    for param_path, value in strings:
        # 1. Try URL parse first
        host = _extract_host_from_url(value)
        if host and _is_dangerous_ip(host):
            return DetectorResult(
                matched=True,
                detector_name="ssrf_private_ip",
                detail=f"SSRF detected in param '{param_path}': private/internal IP {host}",
            )

        # 2. Bare IP fallback
        stripped = value.strip()
        if _BARE_IPV4_RE.match(stripped) or _BARE_IPV6_RE.match(stripped):
            # Strip brackets for IPv6
            bare = stripped.strip("[]")
            if _is_dangerous_ip(bare):
                return DetectorResult(
                    matched=True,
                    detector_name="ssrf_private_ip",
                    detail=f"SSRF detected in param '{param_path}': private/internal IP {bare}",
                )

    return DetectorResult(matched=False, detector_name="ssrf_private_ip")
