"""Flask extensions, instantiated at import time and bound in the factory.

Flask-Limiter only enforces a limit that was attached to the view function
*before* the app was built, so the limiter has to live here rather than being
applied inside ``create_app``. The configured limit strings are therefore
resolved lazily, per request, through the callables below.
"""

from __future__ import annotations

from flask import current_app, g, request
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


def ip_key() -> str:
    """Rate-limit bucket for the caller.

    ``ProxyFix`` is installed by the factory when ``BEHIND_PROXY`` is set, so
    this is the real client address there. Forwarded headers are ignored
    otherwise, because anyone could spoof one and sidestep the limit.
    """
    return f"ip:{request.remote_addr or 'unknown'}"


def username_key() -> str:
    """Rate-limit bucket for the account being targeted.

    Normalised and truncated so a flood of junk usernames cannot grow the
    limiter's key space without bound.
    """
    username = (request.form.get("username") or "anonymous").strip().lower()
    return f"user:{username[:64]}"


def attempt_failed(response) -> bool:  # noqa: ANN001 - flask Response
    """Only failed attempts consume quota.

    Someone who changes their password correctly should not be locked out of
    doing it again, while an attacker guessing passwords burns the budget.
    """
    return bool(getattr(g, "attempt_failed", False))


def _limit(attribute: str):
    """Read a limit string from the loaded config at request time."""

    def resolve() -> str:
        return getattr(current_app.extensions["sspr_config"], attribute)

    return resolve


per_ip_limit = _limit("rate_limit_per_ip")
per_user_limit = _limit("rate_limit_per_user")

limiter = Limiter(key_func=ip_key)
