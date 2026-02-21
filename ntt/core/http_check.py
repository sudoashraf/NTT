"""
HTTP / HTTPS endpoint health check.

Uses Python's built-in ``urllib`` so there is zero dependency on ``requests``
or ``curl``.  Falls back to ``curl`` for TLS/certificate detail when available.
"""

from __future__ import annotations

import ssl
import socket
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from typing import Optional

from ntt.config import DEFAULT_HTTP_TIMEOUT
from ntt.core.utils import (
    Status,
    TestResult,
    run_command,
    check_tool_available,
)


def _normalise_url(target: str) -> str:
    """Ensure *target* has a scheme prefix."""
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _get_cert_expiry(hostname: str, port: int = 443) -> Optional[str]:
    """Return the notAfter date string of the TLS certificate, or None."""
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, port))
            cert = s.getpeercert()
            return cert.get("notAfter") if cert else None
    except Exception:
        return None


# ── Public API ────────────────────────────────────────────────────────────────


def http_check(target: str, timeout: int = DEFAULT_HTTP_TIMEOUT) -> TestResult:
    """Check an HTTP/HTTPS endpoint and report status, latency, and TLS info."""
    url = _normalise_url(target)
    details: list[str] = []

    try:
        req = Request(url, method="HEAD")
        start = time.perf_counter()
        resp = urlopen(req, timeout=timeout)  # noqa: S310
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        status_code = resp.status
        resp.close()
    except HTTPError as exc:
        elapsed = 0
        status_code = exc.code
    except URLError as exc:
        return TestResult(
            title="HTTP(S) Health Check",
            status=Status.FAILURE,
            target=url,
            summary=f"Connection failed: {exc.reason}",
        )
    except Exception as exc:
        return TestResult(
            title="HTTP(S) Health Check",
            status=Status.ERROR,
            target=url,
            summary=f"Unexpected error: {exc}",
        )

    details.append(f"Status code: {status_code}")
    details.append(f"Response time: {elapsed} ms")

    # TLS certificate check for HTTPS
    if url.startswith("https://"):
        hostname = url.split("//")[1].split("/")[0].split(":")[0]
        expiry = _get_cert_expiry(hostname)
        if expiry:
            details.append(f"TLS cert expires: {expiry}")

    if 200 <= status_code < 400:
        return TestResult(
            title="HTTP(S) Health Check",
            status=Status.SUCCESS,
            target=url,
            summary=f"Endpoint returned HTTP {status_code} in {elapsed} ms.",
            details=details,
        )
    return TestResult(
        title="HTTP(S) Health Check",
        status=Status.PARTIAL,
        target=url,
        summary=f"Endpoint returned HTTP {status_code} (non-OK).",
        details=details,
    )
