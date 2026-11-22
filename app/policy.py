"""Password pre-flight checks.

This is deliberately *not* the authority on what Active Directory will accept.
It exists so that an obviously-bad password produces a readable message instead
of a round-trip and an opaque error code. The domain controller still has the
final say, including on history, age and any fine-grained password policy.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from .config import PolicyConfig

#: The four categories Active Directory counts for its complexity requirement.
_CATEGORIES = ("lowercase", "uppercase", "digit", "symbol")


@dataclass(frozen=True)
class PolicyResult:
    ok: bool
    errors: tuple[str, ...] = ()

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.ok


def describe(policy: PolicyConfig) -> list[str]:
    """Human-readable rules, rendered next to the form."""
    rules = [
        f"At least {policy.min_length} characters long.",
        (
            f"Must use at least {policy.min_character_classes} of these four: "
            "lowercase letter, uppercase letter, number, symbol."
        ),
    ]
    if policy.forbid_username:
        rules.append("Must not contain your username.")
    if policy.forbid_reuse_of_old:
        rules.append("Must be different from your current password.")
    rules.append("Your domain's history and minimum-age rules still apply.")
    return rules


def _categories_present(password: str) -> set[str]:
    present: set[str] = set()
    for char in password:
        if char.islower():
            present.add("lowercase")
        elif char.isupper():
            present.add("uppercase")
        elif char.isdigit():
            present.add("digit")
        elif not char.isspace():
            # Anything printable that is not a letter, digit or space counts as
            # a symbol. The original tool allowed only !&/?%:_@$, which quietly
            # rejected perfectly valid passwords such as ones containing '#'.
            present.add("symbol")
    return present


def validate(
    *,
    username: str,
    old_password: str,
    new_password: str,
    confirm_password: str,
    policy: PolicyConfig,
) -> PolicyResult:
    """Check a proposed password against the configured rules."""

    errors: list[str] = []

    if not username.strip():
        errors.append("Enter your username.")
    if not old_password:
        errors.append("Enter your current password.")
    if not new_password:
        errors.append("Enter a new password.")
        return PolicyResult(False, tuple(errors))

    if new_password != confirm_password:
        errors.append("The new password and its confirmation do not match.")

    # Normalise before length-checking so that a composed and a decomposed
    # form of the same accented password are measured the same way.
    normalised = unicodedata.normalize("NFC", new_password)

    if len(normalised) < policy.min_length:
        errors.append(f"Use at least {policy.min_length} characters.")
    if len(normalised) > policy.max_length:
        errors.append(f"Use no more than {policy.max_length} characters.")

    categories = _categories_present(normalised)
    if len(categories) < policy.min_character_classes:
        missing = [c for c in _CATEGORIES if c not in categories]
        errors.append(
            f"Use at least {policy.min_character_classes} different character "
            f"types. Yours is missing: {', '.join(missing)}."
        )

    if policy.forbid_reuse_of_old and old_password and new_password == old_password:
        errors.append("The new password must be different from your current one.")

    if policy.forbid_username and username.strip():
        account = username.strip().split("\\")[-1].split("@")[0]
        if len(account) >= 3 and account.lower() in normalised.lower():
            errors.append("The new password must not contain your username.")

    return PolicyResult(not errors, tuple(errors))
