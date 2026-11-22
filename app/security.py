"""Transport- and request-level hardening applied to every response."""

from __future__ import annotations

from flask import Flask, Response

_CSP = (
    "default-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; "
    "img-src 'self' data:; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)


def install_security_headers(app: Flask, *, force_https: bool) -> None:
    @app.after_request
    def _headers(response: Response) -> Response:
        # The original page pulled Bootstrap and jQuery from public CDNs, which
        # let a third party inject script into a page that handles passwords.
        # Assets are local now and the CSP enforces it.
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        # Password fields must never be cached by an intermediary or the
        # browser's back-forward cache.
        response.headers.setdefault(
            "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
        )
        response.headers.setdefault("Pragma", "no-cache")
        if force_https:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response
