# Changelog

## 2.0.0 — 2026-11-22

A restructure for production use. **Breaking**: form field names, configuration
mechanism and deployment model all changed. See
[docs/deployment.md](docs/deployment.md#upgrading-from-version-1).

### Security

- **Removed remote command execution.** Version 1 concatenated the username and
  both passwords into a PowerShell command run over SSH, so a username of
  `x; Remove-ADUser -Identity ceo -Confirm:$false` executed as a
  directory-privileged account. The new `ldap` backend has no command
  interpreter in the path; the `winrm` backend base64-encapsulates every
  parameter. Six injection payloads are pinned in `tests/test_winrm_backend.py`.
- **Removed all hardcoded credentials.** Configuration comes from the
  environment, no secret has a default, and startup aborts when one is missing
  or `SECRET_KEY` is under 32 characters. Secret config fields are `repr=False`
  so they cannot leak into tracebacks.
- **Removed `debug=True`** and Flask's development server. Runs under gunicorn.
- **Removed `paramiko.AutoAddPolicy`** along with SSH itself. Both back ends
  validate server certificates by default.
- Added CSRF protection, per-IP and per-username rate limiting, HSTS, a strict
  CSP, `frame-ancestors 'none'` and `no-store` on every response.
- Replaced CDN-hosted Bootstrap and jQuery with local assets — third-party
  script has no business on a page that handles passwords.
- Added a structured JSON audit log that is incapable of carrying password
  material, with a test that fails if it ever does.
- Container runs as UID 10001 with a read-only filesystem and no capabilities.
- Added [SECURITY.md](SECURITY.md), a [threat model](docs/threat-model.md), and
  `scripts/purge-secrets-from-history.sh` for forks of version 1.

### Fixed

- **Failed password changes were reported as successful.** `stderr` was read
  and discarded, and the success message was set unconditionally. Success is
  now reported only when the domain controller confirms the change.
- **`GET /password` raised `UnboundLocalError`**, because `message` was only
  assigned on the POST path. It redirects to the form.
- **The container could not start**: `dockerfile` ran `final.py`, which had been
  renamed to `app.py` six years earlier.
- `e.message` raised `AttributeError` on Python 3, masking the real error.
- The symbol class was restricted to `!&/?%:_@$`, silently rejecting valid
  passwords containing `#`, `*`, `^` and others. Any non-alphanumeric character
  now counts.
- Password length is measured after Unicode NFC normalisation, so composed and
  decomposed accented characters are treated consistently.
- `RATELIMIT_STORAGE_URI` is passed to Flask-Limiter before initialisation;
  setting it afterwards silently left every deployment on per-worker in-memory
  counters.

### Changed

- Python 3.6 → 3.11+; Flask 1.1.2 → 3.1; dropped paramiko 2.7.1 entirely.
- Single `app.py` → an `app/` package with an application factory.
- Two interchangeable back ends (`ldap`, `winrm`) behind one `ADBackend`
  interface, selected by `AD_BACKEND`.
- Default password policy is now 12 characters and 3 of 4 character classes,
  matching AD's own complexity rule, instead of 8 characters requiring all four.
- Form fields renamed: `uname` → `username`, `oldpassword` → `old_password`,
  `newpassword` → `new_password`, `confirmnewpassword` → `confirm_password`.
- Added `/healthz` (liveness) and `/readyz` (directory reachability).
- Added 65 tests, `ruff`, `pyproject.toml`, `docker-compose.yml` and an
  Apache 2.0 licence (the repository previously had none, which meant nobody
  could legally fork and deploy it).

## 1.0.0 — 2020-08-06

Initial proof of concept: Flask form, paramiko SSH to a Windows host, PowerShell
`Set-AdAccountPassword`. Not suitable for production — see
[SECURITY.md](SECURITY.md#known-defects-in-version-1).
