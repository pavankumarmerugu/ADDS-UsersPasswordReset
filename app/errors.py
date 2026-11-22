"""Backend-independent error types.

Routes map these to user-facing messages. The distinction that matters is
between a problem the *user* can fix (wrong current password, policy rejection)
and a problem the *operator* must fix (host unreachable, service account
expired) — the second kind must never be rendered to the user in detail,
because it describes internal infrastructure.
"""

from __future__ import annotations


class PasswordResetError(Exception):
    """Base class for every failure path in a backend."""

    #: Safe to show to the end user.
    user_message = "The password could not be changed. Contact your IT helpdesk."


class AuthenticationFailed(PasswordResetError):
    """The username or current password was wrong."""

    user_message = "The username or current password is incorrect."


class AccountUnusable(PasswordResetError):
    """Locked out, disabled, or expired — the user cannot self-serve."""

    user_message = (
        "This account is locked, disabled or expired and cannot be changed "
        "here. Contact your IT helpdesk."
    )


class PolicyRejected(PasswordResetError):
    """Active Directory refused the new password."""

    user_message = (
        "Your domain rejected this password. It may repeat a recent password, "
        "be too new to change again, or fail a domain-specific rule."
    )


class BackendUnavailable(PasswordResetError):
    """Infrastructure problem. Details go to the log, never to the browser."""

    user_message = (
        "The password service is temporarily unavailable. Please try again "
        "later or contact your IT helpdesk."
    )


class PasswordExpired(PasswordResetError):
    """The password is expired or flagged "must change at next logon".

    Relevant to the LDAP backend only: Active Directory refuses a simple bind
    for these accounts, so the user cannot prove ownership with their old
    password over LDAP even though that is exactly when they need to. See
    docs/architecture.md for the backend trade-off this creates.
    """

    user_message = (
        "Your password has expired, so it cannot be changed here. Sign in at a "
        "domain-joined workstation to set a new one, or contact your IT helpdesk."
    )
