"""Route behaviour, including regressions for the defects in version 1."""

from __future__ import annotations

from app.errors import AuthenticationFailed, BackendUnavailable, PolicyRejected

GOOD = {
    "username": "jdoe",
    "old_password": "OldPassw0rd!",
    "new_password": "Correct-Horse9",
    "confirm_password": "Correct-Horse9",
}


def test_home_renders_the_form(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Change your password" in response.data


def test_get_password_redirects_instead_of_crashing(client):
    """Regression: v1 raised UnboundLocalError on GET /password."""
    response = client.get("/password")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_successful_change_reports_success(client, backend):
    response = client.post("/password", data=GOOD)
    assert response.status_code == 200
    assert b"Your password has been changed." in response.data
    assert backend.calls[0]["username"] == "jdoe"


def test_backend_failure_is_not_reported_as_success(client, backend):
    """Regression: v1 printed 'Password changed successfully' unconditionally."""
    backend.raises = AuthenticationFailed("wrong password")
    response = client.post("/password", data=GOOD)
    assert response.status_code == 400
    assert b"Your password has been changed." not in response.data
    assert b"username or current password is incorrect" in response.data


def test_domain_rejection_is_surfaced(client, backend):
    backend.raises = PolicyRejected("history")
    response = client.post("/password", data=GOOD)
    assert response.status_code == 400
    assert b"domain rejected this password" in response.data


def test_backend_outage_returns_503_without_internal_detail(client, backend):
    backend.raises = BackendUnavailable("ldaps://dc01.corp.internal timed out")
    response = client.post("/password", data=GOOD)
    assert response.status_code == 503
    assert b"temporarily unavailable" in response.data
    assert b"dc01.corp.internal" not in response.data


def test_unexpected_exception_does_not_leak_a_traceback(client, backend):
    backend.raises = RuntimeError("boom: connecting to 10.0.0.5 as svc-sspr")
    response = client.post("/password", data=GOOD)
    assert response.status_code == 500
    assert b"unexpected error" in response.data
    assert b"svc-sspr" not in response.data
    assert b"Traceback" not in response.data


def test_policy_violation_never_reaches_the_backend(client, backend):
    response = client.post("/password", data={**GOOD, "new_password": "short", "confirm_password": "short"})
    assert response.status_code == 400
    assert backend.calls == []


def test_missing_account_and_wrong_password_look_identical(client, backend):
    """No username enumeration: both map to AuthenticationFailed."""
    backend.raises = AuthenticationFailed("no such user")
    missing = client.post("/password", data=GOOD).data
    backend.raises = AuthenticationFailed("wrong password")
    wrong = client.post("/password", data=GOOD).data
    assert missing == wrong


def test_security_headers_are_present(client):
    headers = client.get("/").headers
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "no-store" in headers["Cache-Control"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_page_loads_no_third_party_scripts(client):
    body = client.get("/").data
    for cdn in (b"maxcdn", b"cdnjs", b"googleapis", b"bootstrapcdn"):
        assert cdn not in body


def test_csrf_token_is_required_when_enabled(app):
    app.config["WTF_CSRF_ENABLED"] = True
    response = app.test_client().post("/password", data=GOOD)
    assert response.status_code == 400
    assert b"session expired" in response.data


def test_healthz_does_not_touch_the_directory(client, backend):
    backend.healthy = False
    assert client.get("/healthz").status_code == 200


def test_readyz_reflects_backend_health(client, backend):
    assert client.get("/readyz").status_code == 200
    backend.healthy = False
    assert client.get("/readyz").status_code == 503


def test_passwords_are_never_written_to_the_audit_log(client, caplog):
    caplog.set_level("INFO")
    client.post("/password", data=GOOD)
    combined = "\n".join(record.getMessage() for record in caplog.records)
    assert "Correct-Horse9" not in combined
    assert "OldPassw0rd!" not in combined
    assert "password_change.succeeded" in combined
