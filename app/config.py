"""Configuration, loaded entirely from the environment.

Rule for this module: nothing secret gets a default. A missing secret raises
at start-up rather than silently falling back to something guessable, which is
how the original single-file version ended up with credentials in git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class ConfigError(RuntimeError):
    """Raised at start-up when the environment is incomplete or inconsistent."""


def _get(name: str, default: str | None = None, *, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise ConfigError(
            f"{name} is required. Copy .env.example to .env and fill it in."
        )
    return value or ""


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class PolicyConfig:
    """Client-side-of-AD password rules.

    These are a *pre-flight* check so users get a clear message instead of an
    opaque LDAP error. Active Directory remains the authority: a password that
    passes here can still be rejected by the domain policy, and that rejection
    is surfaced verbatim-ish to the user.
    """

    min_length: int = 12
    max_length: int = 256
    # AD's own "complexity" rule is 3 of 4 categories, so that is the default.
    min_character_classes: int = 3
    forbid_username: bool = True
    forbid_reuse_of_old: bool = True


@dataclass(frozen=True)
class LdapConfig:
    """Direct LDAPS change-password. No Windows hop, no privileged account."""

    server: str = ""
    port: int = 636
    use_ssl: bool = True
    ca_cert_file: str = ""
    validate_cert: bool = True
    base_dn: str = ""
    upn_suffix: str = ""
    connect_timeout: int = 10


@dataclass(frozen=True)
class WinRmConfig:
    """PowerShell over WinRM against a host with the AD management tools."""

    endpoint: str = ""
    auth: str = "ntlm"
    username: str = ""
    password: str = field(default="", repr=False)
    ca_cert_file: str = ""
    validate_cert: bool = True
    read_timeout: int = 30
    operation_timeout: int = 20


@dataclass(frozen=True)
class AppConfig:
    secret_key: str = field(default="", repr=False)
    backend: str = "ldap"
    behind_proxy: bool = False
    proxy_hops: int = 1
    force_https: bool = True
    rate_limit_per_ip: str = "10 per hour"
    rate_limit_per_user: str = "5 per hour"
    rate_limit_storage_uri: str = "memory://"
    log_level: str = "INFO"
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    ldap: LdapConfig = field(default_factory=LdapConfig)
    winrm: WinRmConfig = field(default_factory=WinRmConfig)

    # -- Flask wiring -------------------------------------------------------
    def as_flask_mapping(self) -> dict:
        return {
            "SECRET_KEY": self.secret_key,
            "SESSION_COOKIE_SECURE": self.force_https,
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SAMESITE": "Lax",
            "WTF_CSRF_TIME_LIMIT": 1800,
            "PREFERRED_URL_SCHEME": "https" if self.force_https else "http",
            "MAX_CONTENT_LENGTH": 64 * 1024,
            # Flask-Limiter reads its storage from app.config, so this has
            # to be in place before limiter.init_app() runs.
            "RATELIMIT_STORAGE_URI": self.rate_limit_storage_uri,
            "RATELIMIT_STRATEGY": "fixed-window",
            "RATELIMIT_HEADERS_ENABLED": False,
        }


def load_config() -> AppConfig:
    """Build an AppConfig from os.environ, validating as we go."""

    backend = _get("AD_BACKEND", "ldap").strip().lower()
    if backend not in {"ldap", "winrm"}:
        raise ConfigError(f"AD_BACKEND must be 'ldap' or 'winrm', got {backend!r}")

    config = AppConfig(
        secret_key=_get("SECRET_KEY", required=True),
        backend=backend,
        behind_proxy=_get_bool("BEHIND_PROXY", False),
        proxy_hops=_get_int("PROXY_HOPS", 1),
        force_https=_get_bool("FORCE_HTTPS", True),
        rate_limit_per_ip=_get("RATE_LIMIT_PER_IP", "10 per hour"),
        rate_limit_per_user=_get("RATE_LIMIT_PER_USER", "5 per hour"),
        rate_limit_storage_uri=_get("RATE_LIMIT_STORAGE_URI", "memory://"),
        log_level=_get("LOG_LEVEL", "INFO").upper(),
        policy=PolicyConfig(
            min_length=_get_int("PASSWORD_MIN_LENGTH", 12),
            max_length=_get_int("PASSWORD_MAX_LENGTH", 256),
            min_character_classes=_get_int("PASSWORD_MIN_CLASSES", 3),
            forbid_username=_get_bool("PASSWORD_FORBID_USERNAME", True),
            forbid_reuse_of_old=_get_bool("PASSWORD_FORBID_OLD", True),
        ),
        ldap=LdapConfig(
            server=_get("LDAP_SERVER"),
            port=_get_int("LDAP_PORT", 636),
            use_ssl=_get_bool("LDAP_USE_SSL", True),
            ca_cert_file=_get("LDAP_CA_CERT_FILE"),
            validate_cert=_get_bool("LDAP_VALIDATE_CERT", True),
            base_dn=_get("LDAP_BASE_DN"),
            upn_suffix=_get("LDAP_UPN_SUFFIX"),
            connect_timeout=_get_int("LDAP_CONNECT_TIMEOUT", 10),
        ),
        winrm=WinRmConfig(
            endpoint=_get("WINRM_ENDPOINT"),
            auth=_get("WINRM_AUTH", "ntlm").strip().lower(),
            username=_get("WINRM_USERNAME"),
            password=_get("WINRM_PASSWORD"),
            ca_cert_file=_get("WINRM_CA_CERT_FILE"),
            validate_cert=_get_bool("WINRM_VALIDATE_CERT", True),
            read_timeout=_get_int("WINRM_READ_TIMEOUT", 30),
            operation_timeout=_get_int("WINRM_OPERATION_TIMEOUT", 20),
        ),
    )

    _validate(config)
    return config


def _validate(config: AppConfig) -> None:
    if len(config.secret_key) < 32:
        raise ConfigError(
            "SECRET_KEY must be at least 32 characters. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )

    if config.policy.min_length < 8:
        raise ConfigError("PASSWORD_MIN_LENGTH must be at least 8.")
    if not 1 <= config.policy.min_character_classes <= 4:
        raise ConfigError("PASSWORD_MIN_CLASSES must be between 1 and 4.")

    if config.backend == "ldap":
        missing = [
            name
            for name, value in (
                ("LDAP_SERVER", config.ldap.server),
                ("LDAP_BASE_DN", config.ldap.base_dn),
                ("LDAP_UPN_SUFFIX", config.ldap.upn_suffix),
            )
            if not value
        ]
        if missing:
            raise ConfigError(
                "AD_BACKEND=ldap requires: " + ", ".join(missing)
            )
        # AD refuses password modification over an unencrypted connection, so
        # failing here is clearer than a confusing LDAP error at reset time.
        if not config.ldap.use_ssl:
            raise ConfigError(
                "LDAP_USE_SSL=false is not supported: Active Directory rejects "
                "password changes over cleartext LDAP. Use LDAPS on port 636."
            )
        if not config.ldap.validate_cert:
            _warn_insecure("LDAP_VALIDATE_CERT=false disables LDAPS certificate checks")

    if config.backend == "winrm":
        missing = [
            name
            for name, value in (
                ("WINRM_ENDPOINT", config.winrm.endpoint),
                ("WINRM_USERNAME", config.winrm.username),
                ("WINRM_PASSWORD", config.winrm.password),
            )
            if not value
        ]
        if missing:
            raise ConfigError(
                "AD_BACKEND=winrm requires: " + ", ".join(missing)
            )
        if config.winrm.auth not in {"ntlm", "kerberos", "basic", "certificate"}:
            raise ConfigError(
                "WINRM_AUTH must be one of: ntlm, kerberos, basic, certificate"
            )
        if not config.winrm.endpoint.lower().startswith("https://"):
            raise ConfigError(
                "WINRM_ENDPOINT must use https:// — the service account's "
                "credentials and every user password traverse this link."
            )
        if not config.winrm.validate_cert:
            _warn_insecure("WINRM_VALIDATE_CERT=false disables WinRM certificate checks")


def _warn_insecure(message: str) -> None:
    import logging

    logging.getLogger(__name__).warning(
        "INSECURE CONFIGURATION: %s. Acceptable for a lab, not for production.",
        message,
    )
