"""Audit logging.

Every attempt is recorded, successful or not, because an SSSPR endpoint is a
high-value target and "who tried to change whose password, from where" is the
first question an incident responder asks. The original tool logged nothing.

One hard rule: **no password material, ever.** Not the old one, not the new
one, not a prefix, not a length. The helpers here only accept fields that are
safe to persist.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from flask import g, has_request_context, request

audit_log = logging.getLogger("audit")


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def client_ip() -> str:
    """The caller's address, trusting proxy headers only when configured.

    ``ProxyFix`` is installed in the app factory when ``BEHIND_PROXY`` is set,
    so ``remote_addr`` is already the real client there. When it is not set,
    ``X-Forwarded-For`` is ignored on purpose — otherwise anyone could spoof a
    header and sidestep per-IP rate limiting.
    """
    if not has_request_context():
        return "-"
    return request.remote_addr or "-"


def record(event: str, **fields: Any) -> None:
    payload = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "event": event,
        "request_id": getattr(g, "request_id", "-") if has_request_context() else "-",
        "client_ip": client_ip(),
        "user_agent": (request.user_agent.string[:200] if has_request_context() else "-"),
        **fields,
    }
    audit_log.info(json.dumps(payload, sort_keys=True, default=str))


def configure_logging(level: str) -> None:
    """Plain stdout logging, which is what a container orchestrator wants."""
    root = logging.getLogger()
    if root.handlers:  # pragma: no cover - gunicorn installs its own
        root.setLevel(level)
        return

    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root.addHandler(handler)
    root.setLevel(level)

    # Keep third-party chatter out of the audit trail; ldap3 in particular is
    # extremely verbose at DEBUG and has been known to echo bind arguments.
    for noisy in ("ldap3", "urllib3", "requests_ntlm", "winrm"):
        logging.getLogger(noisy).setLevel(max(logging.INFO, logging.getLevelName(level)))
