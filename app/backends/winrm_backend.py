"""Change a password via ``Set-ADAccountPassword`` over WinRM.

This preserves the original tool's topology — a Linux web tier driving a
Windows host that carries the AD management tools — while removing the two
defects that made that topology dangerous:

1. **No command string is ever built from user input.** The original
   concatenated the username and both passwords straight into a PowerShell
   command, so a username of ``x; Remove-ADUser -Identity ceo -Confirm:$false``
   ran as the service account. Here every value is base64-encoded in Python,
   validated against the base64 alphabet, and decoded *inside* PowerShell into
   a variable. Base64 contains no PowerShell metacharacters, so the user's
   bytes are never parsed as syntax.

2. **No plaintext password on a command line.** Values arrive as base64 and are
   decoded in-process, so they do not appear in the Windows process list, in
   ``Get-History``, or in PowerShell transcription logs the way
   ``-AsPlainText hunter2`` did.

SSH with ``AutoAddPolicy`` is gone: WinRM runs over HTTPS with ordinary
certificate validation, so the transport authenticates the server.
"""

from __future__ import annotations

import base64
import json
import logging
import re

import winrm
from winrm.exceptions import WinRMError, WinRMTransportError

from ..config import WinRmConfig
from ..errors import (
    AccountUnusable,
    AuthenticationFailed,
    BackendUnavailable,
    PolicyRejected,
)
from . import ADBackend

log = logging.getLogger(__name__)

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")

#: Deliberately strict. Active Directory permits more than this in a
#: sAMAccountName, but everything outside this set is far likelier to be an
#: attack than a real account, and the check costs nothing.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")

_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$result = @{ status = 'error'; code = 'unknown'; detail = '' }
$old = $null
$new = $null
try {
    Import-Module ActiveDirectory -ErrorAction Stop | Out-Null

    $identity = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@USER_B64@@'))
    $oldPlain = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@OLD_B64@@'))
    $newPlain = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@NEW_B64@@'))

    $old = ConvertTo-SecureString -String $oldPlain -AsPlainText -Force
    $new = ConvertTo-SecureString -String $newPlain -AsPlainText -Force
    $oldPlain = $null
    $newPlain = $null

    $account = Get-ADUser -Identity $identity -Properties Enabled, LockedOut -ErrorAction Stop
    if (-not $account.Enabled) {
        $result.code = 'account_disabled'
        throw 'disabled'
    }
    if ($account.LockedOut) {
        $result.code = 'account_locked'
        throw 'locked'
    }

    Set-ADAccountPassword -Identity $account.DistinguishedName -OldPassword $old -NewPassword $new -ErrorAction Stop

    $result.status = 'ok'
    $result.code = 'changed'
    $result.detail = ''
}
catch {
    if ($result.code -eq 'unknown') {
        $result.code = $_.Exception.GetType().Name
    }
    $result.detail = $_.Exception.Message
}
finally {
    $old = $null
    $new = $null
    $oldPlain = $null
    $newPlain = $null
    [GC]::Collect()
}
Write-Output ($result | ConvertTo-Json -Compress)
"""

_HEALTH_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
Write-Output (@{ status = 'ok'; dc = (Get-ADDomainController -Discover -ErrorAction Stop).HostName } | ConvertTo-Json -Compress)
"""


def _encode(value: str) -> str:
    """Base64-encode a value for safe transport into the PowerShell script."""
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    # By construction this always holds; asserting it makes the safety property
    # explicit rather than implied, and fails loudly if _encode ever changes.
    if not _BASE64_RE.fullmatch(encoded):
        raise ValueError("base64 encoding produced unexpected characters")
    return encoded


class WinRmBackend(ADBackend):
    name = "winrm"

    def __init__(self, config: WinRmConfig) -> None:
        self._config = config

    def _session(self) -> winrm.Session:
        return winrm.Session(
            self._config.endpoint,
            auth=(self._config.username, self._config.password),
            transport=self._config.auth,
            server_cert_validation=(
                "validate" if self._config.validate_cert else "ignore"
            ),
            ca_trust_path=self._config.ca_cert_file or None,
            read_timeout_sec=self._config.read_timeout,
            operation_timeout_sec=self._config.operation_timeout,
        )

    def _run(self, script: str) -> dict:
        try:
            response = self._session().run_ps(script)
        except (WinRMError, WinRMTransportError, OSError) as exc:
            log.error("WinRM call to %s failed: %s", self._config.endpoint, exc)
            raise BackendUnavailable(str(exc)) from exc

        stdout = (response.std_out or b"").decode("utf-8", "replace").strip()
        stderr = (response.std_err or b"").decode("utf-8", "replace").strip()

        if response.status_code != 0 and not stdout:
            log.error("WinRM script exited %s: %s", response.status_code, stderr[:500])
            raise BackendUnavailable(f"remote script exited {response.status_code}")

        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            # stderr may quote the script, so it is logged truncated and never
            # returned to the browser.
            log.error("Unparseable WinRM response: %r / %r", stdout[:500], stderr[:500])
            raise BackendUnavailable("unexpected response from the AD host") from exc

    def change_password(
        self, *, username: str, old_password: str, new_password: str
    ) -> None:
        if not _USERNAME_RE.fullmatch(username):
            # Rejected before it reaches the wire at all.
            log.warning("Rejected malformed username: %r", username[:64])
            raise AuthenticationFailed("malformed username")

        script = (
            _SCRIPT.replace("@@USER_B64@@", _encode(username))
            .replace("@@OLD_B64@@", _encode(old_password))
            .replace("@@NEW_B64@@", _encode(new_password))
        )
        result = self._run(script)

        if result.get("status") == "ok":
            return

        raise self._classify(str(result.get("code", "")), str(result.get("detail", "")))

    @staticmethod
    def _classify(code: str, detail: str) -> Exception:
        log.info("WinRM password change refused: code=%s detail=%s", code, detail[:200])
        lowered = detail.lower()

        if code in {"account_disabled", "account_locked"}:
            return AccountUnusable(code)
        if "ADIdentityNotFoundException" in code:
            # Do not disclose whether the account exists.
            return AuthenticationFailed("identity not found")
        if "network password is not correct" in lowered or "0x80070056" in lowered:
            return AuthenticationFailed(detail)
        if "access is denied" in lowered or "unauthorizedaccess" in code.lower():
            return AuthenticationFailed(detail)
        if (
            "ADPasswordComplexityException" in code
            or "length, complexity, or history" in lowered
            or "does not meet the" in lowered
        ):
            return PolicyRejected(detail)
        return PolicyRejected(detail or code)

    def check_health(self) -> None:
        result = self._run(_HEALTH_SCRIPT)
        if result.get("status") != "ok":
            raise BackendUnavailable("AD host reported an unhealthy state")
