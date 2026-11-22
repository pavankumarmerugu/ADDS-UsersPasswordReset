"""Pluggable Active Directory back ends.

Two implementations with a deliberate trade-off between them:

``ldap``
    Talks LDAPS straight to a domain controller and binds **as the user**, so
    the application holds no privileged credential at all. Cannot serve an
    account whose password has already expired, because Active Directory
    refuses the bind.

``winrm``
    Runs ``Set-ADAccountPassword`` on a host with the AD management tools, the
    shape the original tool used. Needs a delegated service account, but can
    serve expired and must-change-at-next-logon accounts.

Both receive the user's input as *data* and never interpolate it into a
command, a filter or a shell string.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..config import AppConfig


class ADBackend(ABC):
    """Everything the web layer is allowed to ask of Active Directory."""

    name: str = "abstract"

    @abstractmethod
    def change_password(
        self, *, username: str, old_password: str, new_password: str
    ) -> None:
        """Change ``username``'s password, proving ownership with the old one.

        Returns ``None`` on success and raises a
        :class:`~app.errors.PasswordResetError` subclass otherwise. It must
        never return normally unless the domain controller confirmed the
        change — the original tool reported success unconditionally.
        """

    @abstractmethod
    def check_health(self) -> None:
        """Raise :class:`~app.errors.BackendUnavailable` if AD is unreachable."""


def build_backend(config: AppConfig) -> ADBackend:
    if config.backend == "ldap":
        from .ldap_backend import LdapBackend

        return LdapBackend(config.ldap)
    if config.backend == "winrm":
        from .winrm_backend import WinRmBackend

        return WinRmBackend(config.winrm)
    raise ValueError(f"Unknown backend: {config.backend!r}")


__all__ = ["ADBackend", "build_backend"]
