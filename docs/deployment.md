# Deploying a fork

## Before anything else

This application accepts a username and a password from an anonymous caller and
relays them to your directory. Treat it as an authentication endpoint, because
that is what it is.

- [ ] Read the [threat model](threat-model.md).
- [ ] Decide on a backend using [architecture.md](architecture.md#choosing).
- [ ] Have your security team review the fork. Do not deploy an unreviewed
      self-service password tool because a README said it was hardened.

## 1. Fork and configure

```bash
git clone https://github.com/<your-org>/ADDS-UsersPasswordReset.git
cd ADDS-UsersPasswordReset
cp .env.example .env

python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env
```

Edit `.env`. The app refuses to start on a missing `SECRET_KEY`, a cleartext
LDAP or WinRM endpoint, or an incomplete backend configuration — a failure at
boot is the intended behaviour, not a bug.

Mount your CA bundle:

```bash
mkdir -p certs
cp /path/to/ad-ca.pem certs/ad-ca.pem    # referenced by LDAP_CA_CERT_FILE
```

## 2. Run it

```bash
docker compose up -d --build
docker compose logs -f sspr
curl -s localhost:8000/healthz   # liveness, does not touch AD
curl -s localhost:8000/readyz    # proves the directory is reachable
```

`docker-compose.yml` binds to `127.0.0.1:8000` deliberately. The container runs
as UID 10001 with a read-only filesystem and all capabilities dropped.

## 3. Terminate TLS in front of it

The app never speaks TLS itself. Put a reverse proxy in front and set
`BEHIND_PROXY=true` so that per-IP rate limiting sees real client addresses.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name password.corp.example.com;

    ssl_certificate     /etc/ssl/certs/password.crt;
    ssl_certificate_key /etc/ssl/private/password.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Second line of defence behind the app's own limiter.
    limit_req_zone $binary_remote_addr zone=sspr:10m rate=10r/m;

    location / {
        limit_req zone=sspr burst=5 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location ~ ^/(healthz|readyz)$ {
        allow 10.0.0.0/8;
        deny  all;
        proxy_pass http://127.0.0.1:8000;
    }
}

server {
    listen 80;
    server_name password.corp.example.com;
    return 301 https://$host$request_uri;
}
```

Set `PROXY_HOPS` to the number of proxies you actually run. Too high and a
client can spoof `X-Forwarded-For` to evade rate limiting; too low and every
request looks like it came from the proxy.

## 4. Share the rate-limit counters

The default `memory://` keeps counters per gunicorn worker. With the shipped
3 workers, a `5 per hour` limit is really 15 per hour, and it resets on every
deploy. For anything beyond a single-worker pilot:

```bash
RATE_LIMIT_STORAGE_URI=redis://redis:6379/0
```

```yaml
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: ["redis-server", "--save", "", "--appendonly", "no"]
```

## 5. Ship the audit log somewhere

Audit events are JSON on stdout, one per line:

```json
{"ts":"2026-11-22T09:14:02+0100","event":"password_change.succeeded",
 "request_id":"3f2a...","client_ip":"10.1.4.77","username":"jdoe","backend":"ldap"}
```

Forward them to your SIEM and alert on:

- a burst of `password_change.failed` from one IP → password spraying;
- `request.rate_limited` in volume → a sustained attack;
- `password_change.error` with `reason: "unhandled"` → a code-level fault.

No password material is ever present in these events, by construction, and
`tests/test_routes.py` holds a test that fails if that ever changes.

## 6. Expose it deliberately

Users who have forgotten their password cannot reach an internal-only page from
outside. That tension is the whole deployment decision:

| Exposure | Trade-off |
|---|---|
| Internal / VPN only | Safest. Does not help a remote user locked out of the VPN. |
| Public, behind WAF + strict rate limits | Useful, and a permanent credential-stuffing target. |
| Public, IP-allowlisted to office ranges | Middle ground, if your users are predictable. |

If you publish it, put a WAF in front, keep the rate limits tight, alert on
`password_change.failed` volume, and account for the fact that this endpoint
lets anyone test a username/password pair against your directory.

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sspr
spec:
  replicas: 2
  selector:
    matchLabels: { app: sspr }
  template:
    metadata:
      labels: { app: sspr }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: sspr
          image: ghcr.io/<your-org>/adds-sspr:2.0.0
          ports: [{ containerPort: 8000 }]
          envFrom:
            - secretRef: { name: sspr-secrets }
            - configMapRef: { name: sspr-config }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          livenessProbe:
            httpGet: { path: /healthz, port: 8000 }
          readinessProbe:
            httpGet: { path: /readyz, port: 8000 }
            periodSeconds: 30
          volumeMounts:
            - { name: ca, mountPath: /certs, readOnly: true }
      volumes:
        - name: ca
          secret: { secretName: sspr-ad-ca }
```

With `replicas: 2` you **must** set `RATE_LIMIT_STORAGE_URI` to a shared Redis,
or each replica counts separately.

## Upgrading from version 1

Version 1 was a single `app.py` driving PowerShell over SSH. If you are running
it:

1. **Rotate the SSH credentials it used**, and check whether they were ever
   committed — see [SECURITY.md](../SECURITY.md).
2. Decommission the SSH path. Nothing in version 2 uses paramiko.
3. Set `AD_BACKEND=winrm` to keep the same topology, or `ldap` to drop the
   Windows hop entirely.
4. Form fields were renamed (`uname` → `username`, `oldpassword` →
   `old_password`, `newpassword` → `new_password`, `confirmnewpassword` →
   `confirm_password`). Anything that scripted the old form needs updating.
5. The password rules changed: minimum 12 characters and 3 of 4 character
   classes by default, instead of 8 characters requiring all four classes from
   a restricted symbol set. Tune with `PASSWORD_*` variables.
