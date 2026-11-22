from __future__ import annotations

import pytest

from app import create_app
from app.backends import ADBackend
from app.config import AppConfig, PolicyConfig
from app.errors import AuthenticationFailed, BackendUnavailable


class FakeBackend(ADBackend):
    """Records calls and raises whatever the test asks it to."""

    name = "fake"

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.raises: Exception | None = None
        self.healthy = True

    def change_password(self, *, username, old_password, new_password) -> None:
        self.calls.append(
            {
                "username": username,
                "old_password": old_password,
                "new_password": new_password,
            }
        )
        if self.raises is not None:
            raise self.raises

    def check_health(self) -> None:
        if not self.healthy:
            raise BackendUnavailable("down")


@pytest.fixture
def config() -> AppConfig:
    return AppConfig(
        secret_key="x" * 48,
        backend="ldap",
        force_https=False,
        rate_limit_per_ip="100 per hour",
        rate_limit_per_user="100 per hour",
        policy=PolicyConfig(min_length=12, min_character_classes=3),
    )


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def app(config, backend, monkeypatch):
    monkeypatch.setattr("app.build_backend", lambda _cfg: backend)
    application = create_app(config)
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_failure() -> Exception:
    return AuthenticationFailed("nope")
