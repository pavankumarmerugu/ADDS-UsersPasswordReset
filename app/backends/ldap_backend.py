"""Change a password by binding to a domain controller as the user over LDAPS.

Why this is the default backend:

* The application never holds a privileged credential. The user's own old
  password is the only authority used, so a compromise of this service does
  not hand an attacker the ability to reset arbitrary accounts.
* There is no shell, no PowerShell and no command string anywhere in the path,
  which removes the injection class entirely rather than escaping around it.
* One hop instead of two: no Windows jump box to patch and monitor.

The cost is documented in :mod:`app.errors`: an account whose password has
already expired cannot bind, and therefore cannot self-serve here.
"""

from __future__ import annotations

import contextlib
import logging
import re
import ssl

from ldap3 import SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.extend.microsoft.modifyPassword import ad_modify_password

from ..config import LdapConfig
from ..errors import (
    AccountUnusable,
    AuthenticationFailed,
    BackendUnavailable,
    PasswordExpired,
    PolicyRejected,
)
from . import ADBackend

log = logging.getLogger(__name__)

#: Active Directory hides the real reason for a failed bind behind a numeric
#: sub-code in the diagnostic message, e.g. "... comment: AcceptSecurityContext
#: error, data 52e, v4563". These are the ones worth distinguishing.
_BIND_SUBCODES = {
    "525": AuthenticationFailed,   # no such user
    "52e": AuthenticationFailed,   # wrong password
    "530": AccountUnusable,        # not permitted to log on at this time
    "531": AccountUnusable,        # not permitted to log on at this workstation
    "532": PasswordExpired,        # password expired
    "533": AccountUnusable,        # account disabled
    "701": AccountUnusable,        # account expired
    "773": PasswordExpired,        # must change password at next logon
    "775": AccountUnusable,        # account locked out
}

_SUBCODE_RE = re.compile(r"data ([0-9a-f]{3})", re.IGNORECASE)


class LdapBackend(ADBackend):
    name = "ldap"

    def __init__(self, config: LdapConfig) -> None:
        self._config = config

    # -- connection plumbing ------------------------------------------------
    def _server(self) -> Server:
        tls = Tls(
            validate=ssl.CERT_REQUIRED if self._config.validate_cert else ssl.CERT_NONE,
            ca_certs_file=self._config.ca_cert_file or None,
            version=ssl.PROTOCOL_TLS_CLIENT,
        )
        return Server(
            self._config.server,
            port=self._config.port,
            use_ssl=self._config.use_ssl,
            tls=tls,
            connect_timeout=self._config.connect_timeout,
        )

    def _bind_as_user(self, username: str, password: str) -> Connection:
        upn = f"{username}@{self._config.upn_suffix}"
        try:
            return Connection(
                self._server(),
                user=upn,
                password=password,
                authentication=SIMPLE,
                auto_bind=True,
                raise_exceptions=True,
                receive_timeout=self._config.connect_timeout,
            )
        except LDAPBindError as exc:
            raise self._classify_bind_error(exc) from exc
        except LDAPException as exc:
            log.error("LDAP connection to %s failed: %s", self._config.server, exc)
            raise BackendUnavailable(str(exc)) from exc

    @staticmethod
    def _classify_bind_error(exc: LDAPBindError) -> Exception:
        match = _SUBCODE_RE.search(str(exc))
        subcode = match.group(1).lower() if match else ""
        error_class = _BIND_SUBCODES.get(subcode, AuthenticationFailed)
        # The sub-code is safe to log (it is not the password) and is the single
        # most useful thing an operator can have when a user reports a failure.
        log.info("LDAP bind refused, AD sub-code=%s -> %s", subcode or "?", error_class.__name__)
        return error_class(f"bind refused (data {subcode or 'unknown'})")

    def _own_dn(self, connection: Connection, username: str) -> str:
        """Look up the bound user's own DN.

        ``sAMAccountName`` is passed to ldap3 as a parameter rather than
        concatenated, so a username containing LDAP filter metacharacters
        such as ``*`` or ``)`` cannot alter the filter.
        """
        ok = connection.search(
            search_base=self._config.base_dn,
            search_filter="(&(objectClass=user)(sAMAccountName={0}))",
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
            parameters=[username],
        )
        if not ok or not connection.entries:
            # The bind succeeded, so the account exists; failing here means the
            # account lives outside LDAP_BASE_DN.
            log.error(
                "User %r bound successfully but was not found under %s",
                username,
                self._config.base_dn,
            )
            raise BackendUnavailable("account not found under the configured base DN")
        return str(connection.entries[0].distinguishedName)

    # -- public API ---------------------------------------------------------
    def change_password(
        self, *, username: str, old_password: str, new_password: str
    ) -> None:
        connection = self._bind_as_user(username, old_password)
        try:
            user_dn = self._own_dn(connection, username)
            changed = ad_modify_password(
                connection, user_dn, new_password, old_password
            )
            if not changed:
                raise self._classify_modify_error(connection)
        except LDAPException as exc:
            log.error("LDAP password modify failed for %r: %s", username, exc)
            raise BackendUnavailable(str(exc)) from exc
        finally:
            with contextlib.suppress(LDAPException):
                connection.unbind()

    @staticmethod
    def _classify_modify_error(connection: Connection) -> Exception:
        result = connection.result or {}
        description = str(result.get("description", ""))
        message = str(result.get("message", ""))
        log.info("LDAP modify rejected: %s / %s", description, message)
        if "constraintViolation" in description or "0000052D" in message.upper():
            # 0x52D is "password does not meet length/complexity/history".
            return PolicyRejected(description)
        if "insufficientAccessRights" in description:
            return AuthenticationFailed(description)
        return PolicyRejected(description or "password change refused")

    def check_health(self) -> None:
        try:
            # An anonymous connect is enough to prove the DC answers on LDAPS
            # and that its certificate validates; no bind is attempted.
            connection = Connection(self._server(), raise_exceptions=True)
            connection.open()
            connection.unbind()
        except LDAPException as exc:
            raise BackendUnavailable(str(exc)) from exc
