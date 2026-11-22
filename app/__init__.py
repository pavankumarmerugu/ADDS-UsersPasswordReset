"""Application factory for the Active Directory self-service password reset tool."""

from __future__ import annotations

import logging

from flask import Flask, g, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from . import policy
from .audit import configure_logging, new_request_id, record
from .backends import build_backend
from .config import AppConfig, load_config
from .extensions import csrf, limiter
from .security import install_security_headers

__version__ = "2.0.0"

log = logging.getLogger(__name__)


def create_app(config: AppConfig | None = None) -> Flask:
    config = config or load_config()
    configure_logging(config.log_level)

    app = Flask(__name__)
    app.config.update(config.as_flask_mapping())
    app.extensions["sspr_config"] = config

    if config.behind_proxy:
        # Without this every request appears to come from the reverse proxy,
        # and per-IP rate limiting protects nobody.
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=config.proxy_hops, x_proto=config.proxy_hops
        )

    # Registered before CSRF so that a rejected request still carries a
    # correlation id: Flask runs before_request hooks in registration order.
    @app.before_request
    def _assign_request_id() -> None:
        g.request_id = new_request_id()
        g.attempt_failed = False

    csrf.init_app(app)
    limiter.init_app(app)
    install_security_headers(app, force_https=config.force_https)

    app.extensions["sspr_backend"] = build_backend(config)

    from .routes import bp

    app.register_blueprint(bp)

    _install_request_hooks(app)

    log.info(
        "Self-service password reset %s started with the %r backend",
        __version__,
        config.backend,
    )
    return app


def _render_with_banner(app: Flask, banner: str, status: int):
    return (
        render_template(
            "password.html",
            rules=policy.describe(app.extensions["sspr_config"].policy),
            banner=banner,
            banner_category="error",
        ),
        status,
    )


def _install_request_hooks(app: Flask) -> None:
    from flask_limiter.errors import RateLimitExceeded
    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def _csrf_error(error: CSRFError):
        record("request.csrf_failed", reason=error.description)
        return _render_with_banner(
            app,
            "Your session expired before the form was submitted. Please try again.",
            400,
        )

    @app.errorhandler(RateLimitExceeded)
    def _rate_limited(error: RateLimitExceeded):
        record("request.rate_limited", limit=str(error.limit.limit))
        return _render_with_banner(
            app,
            "Too many attempts. Wait a few minutes before trying again, or "
            "contact your IT helpdesk.",
            429,
        )


__all__ = ["create_app", "__version__"]
