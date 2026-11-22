# Threat model

Scope: the self-service password change flow. Out of scope: the security of
Active Directory itself, and the reverse proxy you place in front.

## What an attacker wants

1. To change someone else's password.
2. To execute code on a host that can reach the directory.
3. To harvest credentials in transit.
4. To confirm whether a username exists, or whether a password is valid.
5. To lock accounts out at scale.

## Assets

| Asset | Where it lives | Exposure |
|---|---|---|
| User's current password | Request body, process memory | Never logged, never persisted |
| User's new password | Request body, process memory | Never logged, never persisted |
| `SECRET_KEY` | Environment | Signs CSRF tokens |
| Service account credential (`winrm` only) | Environment | Can change passwords in the delegated OU |
| Audit log | stdout | Usernames and IPs, no password material |

## Threats and controls

### T1 — Command injection through form input

**Version 1 was vulnerable.** It built a PowerShell command by concatenation:

```python
p.exec_command("Set-AdAccountPassword -Identity " + user + " -OldPassword ...")
```

A username of `x; Remove-ADUser -Identity ceo -Confirm:$false` executed as the
SSH service account, which by definition held AD write rights — full directory
compromise from an unauthenticated web form.

**Controls now:**
- The `ldap` backend has no command interpreter in the path at all.
- The `winrm` backend base64-encodes every user value in Python and decodes it
  inside PowerShell. Base64's alphabet contains no PowerShell metacharacter, so
  user bytes are never parsed as syntax.
- Usernames are additionally validated against `^[A-Za-z0-9._\-]{1,64}$` before
  reaching the wire.
- LDAP searches pass `sAMAccountName` as a parameter, so filter metacharacters
  such as `*` and `)` cannot alter the filter.
- `tests/test_winrm_backend.py` runs six injection payloads and asserts none
  appears as syntax in the generated script.

**Residual risk:** a defect in `pywinrm` or `ldap3` itself. Keep them patched.

### T2 — Credential theft in transit

Version 1 served HTTP, used SSH with `AutoAddPolicy` (accepting any host key,
so trivially machine-in-the-middle-able), and loaded Bootstrap and jQuery from
public CDNs onto a page handling passwords.

**Controls:** TLS is terminated by the proxy and `FORCE_HTTPS` sets HSTS and
secure cookies; LDAPS and WinRM/HTTPS both validate certificates by default and
log a warning when disabled; all page assets are local and a CSP with
`default-src 'self'` forbids third-party origins.

**Residual risk:** the app does not terminate TLS itself. A misconfigured proxy
exposes everything. `FORCE_HTTPS=true` cannot enforce what it cannot see.

### T3 — Password spraying and credential stuffing

This endpoint is an oracle: it tells an anonymous caller whether a
username/password pair is valid. That is inherent to self-service password
change and cannot be designed away.

**Controls:** per-IP and per-username rate limits; only *failed* attempts
consume quota; `429` returns the same generic message as other failures; audit
events for every attempt.

**Residual risk:** a distributed attacker rotating source addresses defeats
per-IP limits. The per-username limit still holds, but a slow spray across many
usernames stays under both. **Alert on aggregate `password_change.failed`
volume** — that is your real detection, not the limiter. With `memory://`
storage the limits are per worker and effectively several times looser than
configured.

### T4 — Account lockout as denial of service

Repeated wrong passwords trip the domain lockout policy. An attacker can lock
out every user they can name.

**Controls:** the per-username limit caps attempts well below a typical lockout
threshold; the local policy pre-flight rejects malformed input without
contacting the directory.

**Residual risk:** real, and partly inherent. Set `RATE_LIMIT_PER_USER` below
your domain's lockout threshold, and prefer a lockout policy with automatic
reset over one requiring administrator intervention.

### T5 — Username enumeration

**Control:** "no such user" and "wrong password" both map to
`AuthenticationFailed` and render the identical page.
`test_missing_account_and_wrong_password_look_identical` asserts the responses
are byte-identical.

**Residual risk:** timing. An LDAP bind for a non-existent user may return
measurably faster than one for a valid user with a wrong password. Not
mitigated; mitigating it properly requires constant-time padding that would make
the service feel broken under load.

### T6 — CSRF

Version 1 had no token at all, so any site could submit the form on a
logged-in user's behalf.

**Control:** `Flask-WTF` CSRF on every POST; `SameSite=Lax`, `HttpOnly`,
`Secure` cookies; `frame-ancestors 'none'` and `X-Frame-Options: DENY` prevent
clickjacking. An expired token gets a clear message rather than a 400 page.

### T7 — Secret exposure

Version 1 hardcoded the SSH password and the Flask secret key in a file that was
committed to a public repository. [SECURITY.md](../SECURITY.md) covers the
cleanup.

**Controls:** every secret comes from the environment and has no default;
`SECRET_KEY` under 32 characters aborts startup; `.gitignore` excludes `.env`,
`*.pem` and `*.key`; config dataclasses mark secret fields `repr=False` so they
do not leak into tracebacks or logs; nothing is baked into the image.

**Residual risk:** `.env` on disk is readable by anyone who can read the host.
Use a real secret store in production.

### T8 — Information disclosure through errors

Version 1 ran `app.run(debug=True, host='0.0.0.0')`, exposing the Werkzeug
interactive debugger — remote code execution for anyone who could reach it —
and printed raw stderr from the remote command.

**Controls:** gunicorn, never the development server; a catch-all handler
returns a generic message and logs the traceback server-side; backend errors
are mapped to a fixed set of user-safe messages; infrastructure detail
(hostnames, service account names) stays in the log.
`test_unexpected_exception_does_not_leak_a_traceback` pins this.

### T9 — Compromise of the application host

**With `AD_BACKEND=ldap`:** the app holds no directory credential. An attacker
who owns the container can intercept passwords typed *while they are there*,
which is bad — but they cannot reset arbitrary accounts.

**With `AD_BACKEND=winrm`:** they get the service account, and with it password
reset rights across the delegated OU. This is the strongest argument for the
LDAP backend.

**Controls:** non-root UID 10001, read-only filesystem, all capabilities
dropped, `no-new-privileges`, no state at rest.

### T10 — Supply chain

Version 1 pinned Flask 1.1.2 and paramiko 2.7.1 and never moved; both
accumulated published CVEs.

**Controls:** compatible-release pins so rebuilds pick up patches;
`pip-audit` in `requirements-dev.txt`; a slim base image rebuilt on a schedule.
Enable Dependabot or equivalent on your fork.

## Deliberately out of scope

- **Forgotten passwords.** Users must know their current password. Adding
  recovery (security questions, email, SMS, MFA) means building an identity
  proofing system, and a weak one is worse than a helpdesk call.
- **MFA on the change itself.** A worthwhile addition if you have an MFA
  provider; it would sit in front of the form.
- **Password breach checking** (for example Have I Been Pwned's k-anonymity
  range API). A good enhancement; not implemented.
- **Self-service account unlock.** Often requested alongside this; it has a
  different and more dangerous threat model.
