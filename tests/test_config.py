from __future__ import annotations

import pytest

from app.config import ConfigError, load_config

MINIMAL_LDAP = {
    "SECRET_KEY": "k" * 48,
    "AD_BACKEND": "ldap",
    "LDAP_SERVER": "dc01.corp.example.com",
    "LDAP_BASE_DN": "DC=corp,DC=example,DC=com",
    "LDAP_UPN_SUFFIX": "corp.example.com",
}


def _env(monkeypatch, **overrides):
    for key in list(MINIMAL_LDAP) + [
        "WINRM_ENDPOINT", "WINRM_USERNAME", "WINRM_PASSWORD",
        "LDAP_USE_SSL", "PASSWORD_MIN_LENGTH", "AD_BACKEND",
        "RATE_LIMIT_STORAGE_URI",
    ]:
        monkeypatch.delenv(key, raising=False)
    for key, value in {**MINIMAL_LDAP, **overrides}.items():
        if value is not None:
            monkeypatch.setenv(key, value)


def test_minimal_ldap_config_loads(monkeypatch):
    _env(monkeypatch)
    assert load_config().backend == "ldap"


def test_missing_secret_key_fails_fast(monkeypatch):
    _env(monkeypatch, SECRET_KEY=None)
    with pytest.raises(ConfigError, match="SECRET_KEY"):
        load_config()


def test_short_secret_key_is_rejected(monkeypatch):
    _env(monkeypatch, SECRET_KEY="too-short")
    with pytest.raises(ConfigError, match="at least 32"):
        load_config()


def test_cleartext_ldap_is_refused(monkeypatch):
    _env(monkeypatch, LDAP_USE_SSL="false")
    with pytest.raises(ConfigError, match="cleartext"):
        load_config()


def test_cleartext_winrm_endpoint_is_refused(monkeypatch):
    _env(
        monkeypatch,
        AD_BACKEND="winrm",
        WINRM_ENDPOINT="http://adtools:5985/wsman",
        WINRM_USERNAME="CORP\\svc",
        WINRM_PASSWORD="s",
    )
    with pytest.raises(ConfigError, match="https"):
        load_config()


def test_winrm_requires_credentials(monkeypatch):
    _env(monkeypatch, AD_BACKEND="winrm", WINRM_ENDPOINT="https://adtools:5986/wsman")
    with pytest.raises(ConfigError, match="WINRM_USERNAME"):
        load_config()


def test_unknown_backend_is_rejected(monkeypatch):
    _env(monkeypatch, AD_BACKEND="telnet")
    with pytest.raises(ConfigError, match="AD_BACKEND"):
        load_config()


def test_secrets_are_not_in_the_repr(monkeypatch):
    _env(monkeypatch)
    config = load_config()
    assert "k" * 48 not in repr(config)


def test_rate_limit_storage_is_handed_to_flask_limiter(monkeypatch):
    """Regression: the configured storage URI must reach Flask-Limiter.

    Setting it after init_app() silently left every deployment on per-worker
    in-memory counters, making the effective limit N x the configured value.
    """
    _env(monkeypatch)
    monkeypatch.setenv("RATE_LIMIT_STORAGE_URI", "redis://redis:6379/0")
    mapping = load_config().as_flask_mapping()
    assert mapping["RATELIMIT_STORAGE_URI"] == "redis://redis:6379/0"
