# Least-privilege Active Directory setup

## `AD_BACKEND=ldap` — nothing to delegate

This is the point of the LDAP backend: it binds **as the end user**, so there is
no service account and nothing to grant. A user already has the right to change
their own password.

What you do need:

1. **LDAPS on your domain controllers.** AD refuses password modification over
   cleartext LDAP, and the config loader refuses to start without it.
2. **The issuing CA's certificate**, as a PEM bundle, mounted into the container
   and pointed at by `LDAP_CA_CERT_FILE`.
3. **`LDAP_SERVER` as a hostname, not an IP** — the certificate is validated
   against the name you connect to.

Verify LDAPS from the container host before deploying:

```bash
openssl s_client -connect dc01.corp.example.com:636 \
  -CAfile ./certs/ad-ca.pem </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

## `AD_BACKEND=winrm` — delegate narrowly

The service account should be able to do exactly one thing: change passwords for
users in one OU. Not Domain Admins. Not Account Operators — that group grants far
more than password rights and is effectively tier-0.

### 1. Create a dedicated account

```powershell
New-ADUser -Name 'svc-sspr' `
    -SamAccountName 'svc-sspr' `
    -UserPrincipalName 'svc-sspr@corp.example.com' `
    -Path 'OU=ServiceAccounts,DC=corp,DC=example,DC=com' `
    -AccountPassword (Read-Host -AsSecureString 'Password') `
    -PasswordNeverExpires $false `
    -CannotChangePassword $false `
    -Enabled $true
```

Consider a group Managed Service Account (gMSA) instead if your WinRM
authentication method supports it — it removes the stored password entirely.

### 2. Delegate password rights on the target OU only

```powershell
$ou = 'OU=Staff,DC=corp,DC=example,DC=com'

dsacls $ou /I:S /G 'CORP\svc-sspr:CA;Reset Password;user'
dsacls $ou /I:S /G 'CORP\svc-sspr:CA;Change Password;user'
dsacls $ou /I:S /G 'CORP\svc-sspr:RPWP;pwdLastSet;user'
```

`/I:S` applies to descendant *user* objects only. Repeat per OU; never grant at
the domain root, and never include an OU holding privileged accounts.

### 3. Confirm the account cannot do anything else

```powershell
# Should return only the ACEs granted above.
dsacls 'OU=Staff,DC=corp,DC=example,DC=com' | Select-String 'svc-sspr'

# Should be empty — the account must not be in any privileged group.
Get-ADPrincipalGroupMembership svc-sspr | Select-Object Name
```

### 4. Lock the account down further

- **Deny interactive and remote-desktop logon** everywhere via Group Policy
  (`Deny log on locally`, `Deny log on through Remote Desktop Services`).
- **Restrict `Log on to`** to the AD management host only.
- Add it to the **Protected Users** group only after testing — that group
  disables NTLM, which breaks `WINRM_AUTH=ntlm`. Use Kerberos if you want both.
- Enable **auditing** on the OU so delegated password changes are logged
  independently of this application's own audit trail.

### 5. Configure WinRM over HTTPS

Port 5985 is cleartext; the config loader rejects it. Set up an HTTPS listener
with a certificate from your internal CA:

```powershell
$cert = New-SelfSignedCertificate -DnsName 'adtools01.corp.example.com' `
    -CertStoreLocation Cert:\LocalMachine\My   # use your CA in production

New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * `
    -CertificateThumbPrint $cert.Thumbprint -Force

Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false

New-NetFirewallRule -DisplayName 'WinRM HTTPS from SSPR' -Direction Inbound `
    -Protocol TCP -LocalPort 5986 -RemoteAddress <sspr-host-ip> -Action Allow
```

The firewall rule matters: restrict 5986 to the SSPR host's address. A WinRM
endpoint reachable from the whole network is a lateral-movement target.

## Monitoring

Correlate the application's audit events with Windows Security events:

| Event | Where | Meaning |
|---|---|---|
| `password_change.succeeded` | app stdout | The app believes a change completed |
| `4723` | DC Security log | A user attempted to change their own password |
| `4724` | DC Security log | An administrative reset — **should not appear** from `svc-sspr` |
| `password_change.failed` bursts | app stdout | Password spraying in progress |

A `4724` attributed to the service account means something is using it for
administrative resets. Investigate.
