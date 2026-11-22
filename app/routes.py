"""HTTP layer. Thin on purpose: validate, delegate, report honestly."""

from __future__ import annotations

import logging

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from . import policy
from .audit import record
from .errors import BackendUnavailable, PasswordResetError
from .extensions import (
    attempt_failed,
    limiter,
    per_ip_limit,
    per_user_limit,
    username_key,
)

log = logging.getLogger(__name__)

bp = Blueprint("reset", __name__)


def _config():
    return current_app.extensions["sspr_config"]


def _backend():
    return current_app.extensions["sspr_backend"]


def _render_form(status_code: int = 200):
    config = _config()
    return (
        render_template("password.html", rules=policy.describe(config.policy)),
        status_code,
    )


@bp.get("/")
def home():
    return _render_form()


@bp.route("/password", methods=["GET", "POST"])
@limiter.limit(
    per_ip_limit, methods=["POST"], deduct_when=attempt_failed
)
@limiter.limit(
    per_user_limit,
    key_func=username_key,
    methods=["POST"],
    deduct_when=attempt_failed,
)
def change_password():
    # A GET here used to raise UnboundLocalError because `message` was only
    # assigned on the POST path. The form is simply re-rendered now.
    if request.method == "GET":
        return redirect(url_for("reset.home"))

    config = _config()
    username = (request.form.get("username") or "").strip()
    old_password = request.form.get("old_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    result = policy.validate(
        username=username,
        old_password=old_password,
        new_password=new_password,
        confirm_password=confirm_password,
        policy=config.policy,
    )
    if not result.ok:
        g.attempt_failed = True
        record("password_change.rejected", username=username, reason="local_policy")
        for message in result.errors:
            flash(message, "error")
        return _render_form(status_code=400)

    try:
        _backend().change_password(
            username=username,
            old_password=old_password,
            new_password=new_password,
        )
    except PasswordResetError as exc:
        g.attempt_failed = True
        record(
            "password_change.failed",
            username=username,
            backend=_backend().name,
            reason=type(exc).__name__,
        )
        flash(exc.user_message, "error")
        status = 503 if isinstance(exc, BackendUnavailable) else 400
        return _render_form(status_code=status)
    except Exception:  # noqa: BLE001 - last line of defence
        g.attempt_failed = True
        # An unexpected exception must not reach the user as a stack trace, and
        # must never be reported as success.
        log.exception("Unhandled error changing password for %r", username)
        record(
            "password_change.error",
            username=username,
            backend=_backend().name,
            reason="unhandled",
        )
        flash(
            "The password service hit an unexpected error. Contact your IT "
            "helpdesk.",
            "error",
        )
        return _render_form(status_code=500)

    # Reached only when the domain controller confirmed the change.
    record("password_change.succeeded", username=username, backend=_backend().name)
    flash("Your password has been changed.", "success")
    return _render_form()


@bp.get("/healthz")
@limiter.exempt
def healthz():
    """Liveness. Deliberately does not touch Active Directory."""
    return {"status": "ok"}, 200


@bp.get("/readyz")
@limiter.limit("30 per minute")
def readyz():
    """Readiness: can this instance actually reach the directory?"""
    try:
        _backend().check_health()
    except Exception as exc:  # noqa: BLE001
        log.warning("Readiness check failed: %s", exc)
        return {"status": "unavailable", "backend": _backend().name}, 503
    return {"status": "ok", "backend": _backend().name}, 200
