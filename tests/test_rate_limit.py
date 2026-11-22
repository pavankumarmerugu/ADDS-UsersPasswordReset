from __future__ import annotations

import pytest

from app import create_app
from app.config import AppConfig, PolicyConfig
from app.errors import AuthenticationFailed

GOOD = {
    "username": "jdoe",
    "old_password": "OldPassw0rd!",
    "new_password": "Correct-Horse9",
    "confirm_password": "Correct-Horse9",
}


@pytest.fixture
def limited_app(backend, monkeypatch):
    monkeypatch.setattr("app.build_backend", lambda _cfg: backend)
    application = create_app(
        AppConfig(
            secret_key="x" * 48,
            force_https=False,
            rate_limit_per_ip="3 per hour",
            rate_limit_per_user="3 per hour",
            policy=PolicyConfig(min_length=12, min_character_classes=3),
        )
    )
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return application


def test_repeated_failures_are_throttled(limited_app, backend):
    backend.raises = AuthenticationFailed("wrong")
    client = limited_app.test_client()
    statuses = [client.post("/password", data=GOOD).status_code for _ in range(5)]
    assert statuses[:3] == [400, 400, 400]
    assert 429 in statuses
    # The backend stops being contacted once the limit trips.
    assert len(backend.calls) == 3


def test_successful_changes_do_not_consume_quota(limited_app, backend):
    client = limited_app.test_client()
    statuses = [client.post("/password", data=GOOD).status_code for _ in range(6)]
    assert statuses == [200] * 6
