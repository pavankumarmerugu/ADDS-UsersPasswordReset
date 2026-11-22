# Security

## Reporting a vulnerability

Open a private security advisory through GitHub's **Security → Advisories**
tab rather than a public issue. Please include affected version, backend
(`ldap` or `winrm`), and reproduction steps.

---

## Required action for anyone who forked version 1

Version 1 (everything before the 2.0.0 restructure) had defects serious enough
that a running deployment should be treated as compromised until proven
otherwise.

### 1. Rotate the credentials it used

The upstream repository's git history contains a working SSH service account
name, its password and an internal IP address, committed in August 2020 and
removed from the working tree — but **not from the history** — in a later
commit. Removing a secret from the current files does nothing: `git log -p`
still shows it, as does every fork and clone.

If you forked this project, or if your deployment reused any credential from
it:

- [ ] Rotate the SSH / service account password **now**.
- [ ] Rotate `SECRET_KEY`; version 1 hardcoded one in source, so CSRF and
      session tokens signed with it are forgeable by anyone who read the repo.
- [ ] Review authentication logs on the AD management host for use of that
      account from unexpected sources, back to the commit date.
- [ ] Check whether any *user* password was changed through a vulnerable
      deployment, and treat those accounts as suspect.

### 2. Purge the secrets from git history

Rotation is the control that matters; purging stops the value being handed to
every future reader. Do both, in that order.

```bash
pip install git-filter-repo
./scripts/purge-secrets-from-history.sh
```

The script is interactive, takes a backup first, and reads the literal strings
to remove from a file you create locally — so the secrets are never written
into this repository in the course of removing them. Read `scripts/README.md`
before running it.

**History rewriting is disruptive.** Every commit SHA after the earliest
rewritten commit changes. Everyone with a clone must re-clone or rebase. Open
pull requests will need recreating. GitHub may retain the old objects until you
ask Support to run garbage collection, and existing forks keep their own copies
— which is why rotation, not purging, is the control you rely on.

### 3. Known defects in version 1

| | Defect | Effect |
|---|---|---|
| 1 | Form input concatenated into a PowerShell command | Remote command execution as a directory-privileged account, from an unauthenticated web form |
| 2 | Credentials committed to a public repository | Service account disclosure |
| 3 | `app.run(debug=True, host='0.0.0.0')` | Werkzeug interactive debugger exposed; remote code execution |
| 4 | `paramiko.AutoAddPolicy()` | No SSH host key verification; machine-in-the-middle |
| 5 | Hardcoded `secret_key` | Forgeable signed tokens |
| 6 | No CSRF token | Cross-site request forgery on the change form |
| 7 | No rate limiting | Password spraying and lockout denial of service |
| 8 | No TLS | Passwords in cleartext on the wire |
| 9 | `stderr` read but never checked | Failed resets reported to the user as successful |
| 10 | Passwords passed as PowerShell command-line arguments | Plaintext in the Windows process list and transcription logs |
| 11 | Bootstrap and jQuery loaded from public CDNs | Third-party script on a page handling passwords |
| 12 | Flask 1.1.2, paramiko 2.7.1, Python 3.6 | Years of unpatched published CVEs |
| 13 | `GET /password` raised `UnboundLocalError` | Unhandled 500 |
| 14 | `Dockerfile` referenced a renamed file | Container did not start |

Items 1–12 are addressed in 2.0.0 and covered by the
[threat model](docs/threat-model.md); 13 and 14 have regression tests.

---

## Hardening checklist for a production deployment

- [ ] `SECRET_KEY` generated with a CSPRNG, stored in a secret manager
- [ ] TLS terminated in front, `BEHIND_PROXY=true`, `PROXY_HOPS` accurate
- [ ] `RATE_LIMIT_STORAGE_URI` pointing at shared Redis, not `memory://`
- [ ] `RATE_LIMIT_PER_USER` below the domain lockout threshold
- [ ] `AD_BACKEND=ldap` unless expired-password support is required
- [ ] If `winrm`: service account delegated per [ad-delegation.md](docs/ad-delegation.md), not Account Operators
- [ ] Certificate validation left enabled on both backends
- [ ] Audit log shipped to a SIEM with alerting on failure bursts
- [ ] `pip-audit` and image rebuilds in CI
- [ ] Penetration test before exposing it publicly

## What this application never does

- Write password material to a log, a file or a database
- Store a password beyond the lifetime of the request
- Report success unless the domain controller confirmed the change
- Build a shell or PowerShell command from user input
- Start with a missing or weak `SECRET_KEY`
- Accept a cleartext LDAP or WinRM endpoint
