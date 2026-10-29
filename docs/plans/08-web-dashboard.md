# Plan 08 — Web dashboard + hosting on Oracle

## Why

The JSON API in `server.go` already exists (`/api/state`, `/api/repos`, `/api/repo`, `/api/run`, `/api/events` SSE, `/api/export`, the toggles). What's missing is the actual UI, and a safe way to reach it from anywhere — mainly your phone while you're out — instead of only `localhost` on the machine it runs on. Goal: a dashboard where you see the ranked list, open a repo to see *why* sift flagged it (score parts, hot files, contacts, known bugs, leads), and drive runs — hosted on the Oracle VPS behind your domain.

## Two parts, in order: build the UI, then expose it safely.

---

## 8a. The dashboard UI

**Status:** a first version is built: plain JS (no framework), with the ranked list (cards on a phone), the repo page (hot files, how to report, score breakdown, facts, hits by file, status, notes, real/dud marks) and the run panel with the live log. Still to do: the scenes/settings screen, and the plan 4/12 cards once those exist.


### Recommendation
Keep the existing JSON API and build a small single-page app embedded via `go:embed` (as `web/` is today). Keep the JS footprint light — this is a dense data tool, not a marketing site. Good fits, any of:
- **Vanilla + a tiny reactive lib** (Alpine.js) — least build tooling, drops in over the current `web/index.html`.
- **htmx** — server renders HTML fragments, almost no client JS; fits the SSE/live-run model nicely.
- A small **Preact/Vite** build if you want components — heavier toolchain, only if the UI gets complex.

Pick one; don't mix. All ship embedded in the binary, so hosting stays "one executable." Vendor the JS into `web/` rather than loading it from a CDN — the CSP is `default-src 'self'` and should stay that way.

**Phone-first.** The main remote use is checking results on a phone, so the targets table needs a card layout under ~600px (score, name, CVE route, top hot file) and the detail view must read well one-handed. Desktop gets the full table.

### Screens
1. **Targets table** — the ranked list. Columns: score, name, scene, language, popularity, last push, advisories, contact kinds, CVE route, sink/surface/auth counts, status. Sort by score; filter by scene, source, status, language, CVE route, pass/fail; search. This is `/api/repos` (already sorted by score). Paginate once the DB (plan 1) can do it in SQL.
2. **Repo detail** — the "why flagged" view, the heart of it:
   - score with the **part breakdown** (sinks/surface/auth/history/responsiveness/freshness/contact/cve_path/pairing/impact/taint) as a bar or radar so you see what drove it;
   - **hot files** (plan 3a) — the lead list, each a deep link to the file on GitHub at the scanned SHA;
   - the actual **hits** grouped by file with line numbers and snippets (already in `ScanResult.Hits`), linking to the line on GitHub;
   - **contacts** and the **CVE route** (how to report, and who assigns the CVE), plus **known advisories / open security issues** (plan 4);
   - **filter reasons** when it didn't pass;
   - status control (`shortlist`/`digging`/`reported`/`skipped`) + notes — already in `/api/repo` POST.
3. **Run panel** — kick a run (scene picker, stages, force), live log via the existing SSE `/api/events`, progress bar.
4. **Scenes/settings** — toggle categories and queries, test a query (`/api/query/test`), edit weights and filters, the `score_cve_path` toggle. When accessed remotely the token field is read-only (see 8b).

Render all repo-sourced text (descriptions, snippets, contact values, notes) as text, never as HTML — it comes from strangers' repos. No `innerHTML` with API data.

### Nice-to-haves (once the basics work)
Saved views (a filter set you name), tags on repos, keyboard triage (`j`/`k` to move, `s` shortlist, `x` skip) — all client-side over the existing endpoints. A disclosure tracker view: repos with status `reported`, report date, and a 90-day countdown (store report date in notes or a new field).

---

## 8b. Hosting on the Oracle VPS — public, behind strong auth

### Threat model
Once it's on the internet, sift is a tool that **holds a GitHub token, can trigger runs (spending API budget), downloads arbitrary repos, reveals maintainer contacts, and — in your notes — describes vulnerabilities that aren't disclosed yet.** That last one is the real asset. Assume constant scanning, credential stuffing against the login, cross-site requests from pages you visit on your phone, and that one layer will be misconfigured some day. So: several independent layers, each of which **fails closed**.

```
phone --HTTPS--> nginx :443 --auth_request--> oauth2-proxy 127.0.0.1:4180 (GitHub login, only yTax)
                   |
                   +-- authed only --> sift 127.0.0.1:7777 (checks the proxy's user header itself)
```

### Layer 1 — network
- **Oracle VCN security list:** ingress 443 and 80 only (80 just for ACME + redirect), plus 22 restricted to your home IP (or put SSH on Tailscale and close 22 publicly). Oracle's Ubuntu images also ship host `iptables` rules (`/etc/iptables/rules.v4`) that drop everything else — add 80/443 there too, don't flush them.
- sift binds **`127.0.0.1:7777`** and oauth2-proxy **`127.0.0.1:4180`**. Neither is reachable from outside even if the firewall is wrong.
- SSH: keys only (`PasswordAuthentication no`, `PermitRootLogin no`), `fail2ban` sshd jail, `unattended-upgrades` on.

### Layer 2 — nginx (TLS, rate limits, only the real hostname)
Certs from certbot (`certbot --nginx -d sift.ytax.cc` or webroot). Sketch of `deploy/nginx/sift.conf`:

```nginx
limit_req_zone $binary_remote_addr zone=sift:10m       rate=20r/s;
limit_req_zone $binary_remote_addr zone=sift_login:10m rate=10r/m;

# anything that isn't sift.ytax.cc gets nothing (scanners hitting the bare IP)
server { listen 80 default_server;  return 444; }
server { listen 443 ssl default_server; ssl_reject_handshake on; }

server {
    listen 80;
    server_name sift.ytax.cc;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    http2 on;
    server_name sift.ytax.cc;

    ssl_certificate     /etc/letsencrypt/live/sift.ytax.cc/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sift.ytax.cc/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=63072000" always;
    server_tokens off;
    client_max_body_size 1m;

    # oauth2-proxy: sign-in pages and callback
    location /oauth2/ {
        limit_req zone=sift_login burst=10 nodelay;
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Auth-Request-Redirect $request_uri;
    }
    # the subrequest nginx makes for every request below
    location = /oauth2/auth {
        internal;
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Content-Length "";
        proxy_pass_request_body off;
    }

    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;
        auth_request_set $sift_user $upstream_http_x_auth_request_user;

        limit_req zone=sift burst=40 nodelay;
        proxy_pass http://127.0.0.1:7777;
        proxy_set_header Host $host;
        proxy_set_header X-Sift-User $sift_user;   # overwrites anything the client sent
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # live log (SSE): same auth, no buffering, long reads
    location = /api/events {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;
        auth_request_set $sift_user $upstream_http_x_auth_request_user;
        proxy_pass http://127.0.0.1:7777;
        proxy_set_header Host $host;
        proxy_set_header X-Sift-User $sift_user;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
}
```

Every location that reaches sift has `auth_request`. If one ever doesn't, Layer 4 still refuses it.

### Layer 3 — the login: oauth2-proxy with GitHub, only you
`oauth2-proxy` (single Go binary, its own systemd unit and user). You log in with GitHub, so your GitHub 2FA/passkey protects the dashboard and there's no new password to brute-force. Create a GitHub OAuth app (callback `https://sift.ytax.cc/oauth2/callback`), then `/etc/oauth2-proxy/sift.cfg`:

```toml
provider         = "github"
github_users     = ["yTax"]          # only this account gets in
email_domains    = ["*"]             # required by oauth2-proxy; github_users is the real gate
http_address     = "127.0.0.1:4180"
reverse_proxy    = true
set_xauthrequest = true              # -> X-Auth-Request-User for nginx
upstreams        = ["static://202"]
redirect_url     = "https://sift.ytax.cc/oauth2/callback"
cookie_secure    = true
cookie_httponly  = true
cookie_samesite  = "lax"
cookie_expire    = "168h"
cookie_refresh   = "1h"
# client_id / client_secret / cookie_secret come from the env file, not this file
```

Make sure 2FA (ideally a passkey) is on for the GitHub account — it's now the key to the dashboard.

*Optional, strongest:* also require an **mTLS client certificate** in nginx (`ssl_client_certificate` + `ssl_verify_client on`) and install the cert on your phone. Then nobody without the cert even reaches the login page. More setup on the phone; add it later if you want.

### Layer 4 — sift checks for itself (code changes in `server.go` / `main.go`)
Behind the proxy, sift must still refuse anything that didn't come through the login:

- New flags: `-public-host sift.ytax.cc` and `-allow-user yTax`. `guard` accepts `Host: sift.ytax.cc` **only if** the connection is from loopback **and** `X-Sift-User` equals the allowed user (case-insensitive). Otherwise 403. A location missing `auth_request` therefore fails closed. Plain `localhost` keeps working (e.g. over an SSH tunnel).
- Keep the **`X-Sift` header** on every non-GET. For the public host, also require `Origin: https://sift.ytax.cc` on non-GETs and reject `Sec-Fetch-Site: cross-site`. With the `SameSite=Lax` cookie on top, a malicious page open on your phone can't drive the API.
- **Token is read-only remotely:** `POST /api/settings` with a `token` field is rejected when it came via the public host. On the server the token comes from the env file (`token_source` shows "env SIFT_GITHUB_TOKEN").
- `/api/state` stops sending absolute paths (`base`, `dorks_dir`, `sinks_dir`) to remote clients.
- Replace `http.Serve(ln, …)` with an `http.Server` that sets `ReadHeaderTimeout: 10s`, `IdleTimeout: 120s`, `MaxHeaderBytes: 64<<10` (no `WriteTimeout` — it would cut off SSE).
- Tests: table-driven `guard` tests — public host with/without/wrong user header, non-loopback remote, missing `X-Sift`, cross-site `Origin`, token write via public host → each 403; localhost behaviour unchanged.

### Layer 5 — the box and the secrets
- **GitHub token: fine-grained PAT** with "Public repositories" (read-only) access, no extra permissions, 90-day expiry. sift only reads public data, so a leaked token is close to useless. Check that PVR and advisory lookups still return data with it; if PVR comes back unknown, accept that rather than widening the token.
- **Secrets in env files only:** `/etc/sift/sift.env` (`root:root`, `0600`) with `SIFT_GITHUB_TOKEN` and the Discord webhook/bot tokens (plan 6); `/etc/oauth2-proxy/sift.env` with the OAuth client secret and cookie secret. Loaded with `EnvironmentFile=`; never in the repo, never in the UI, never logged.
- **systemd unit** (`deploy/sift.service`), sift as its own unprivileged user:
  ```ini
  [Service]
  User=sift
  Group=sift
  ExecStart=/opt/sift/sift serve -addr 127.0.0.1:7777 -dir /srv/sift -no-browser -public-host sift.ytax.cc -allow-user yTax
  EnvironmentFile=/etc/sift/sift.env
  Restart=on-failure
  NoNewPrivileges=yes
  ProtectSystem=strict
  ProtectHome=yes
  PrivateTmp=yes
  PrivateDevices=yes
  ReadWritePaths=/srv/sift
  CapabilityBoundingSet=
  RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
  RestrictNamespaces=yes
  LockPersonality=yes
  MemoryDenyWriteExecute=yes
  SystemCallFilter=@system-service
  ProtectKernelTunables=yes
  ProtectKernelModules=yes
  ProtectControlGroups=yes
  UMask=0077
  MemoryMax=1G
  ```
  sift downloads untrusted archives; this keeps a hypothetical parser bug boxed into `/srv/sift`. If Semgrep (plan 7) runs here it inherits the same sandbox.
- **The DB is sensitive** (undisclosed bugs in notes, maintainer contacts): `/srv/sift` is `0700` owned by `sift`. Back it up off-box encrypted (`restic` or `age`), never to a public bucket.
- **fail2ban** jail on the nginx access log for repeated 401/403/429 on `/oauth2/`, so credential-stuffing IPs get banned at the firewall.
- Optional: a Discord webhook ping on every successful oauth2-proxy login, so you notice a login that wasn't you.

### Deploy
`deploy/` holds `nginx/sift.conf`, `oauth2-proxy/sift.cfg` (no secrets), `sift.service`, `oauth2-proxy.service`, and a `README.md` with the order: firewall → certbot → oauth2-proxy → sift → nginx reload → run the checks below. A new version is: copy the ARM64 binary to `/opt/sift/`, `systemctl restart sift`.

## Files
- `web/` — the SPA (replacing the placeholder `index.html`), embedded.
- `server.go` — public-host + proxy-user guard, Origin/Sec-Fetch checks, read-only token remotely, trimmed `/api/state`; pagination/filter params on `/api/repos` once SQL-backed.
- `main.go` — `-public-host`, `-allow-user`, `http.Server` with timeouts.
- `deploy/` — as above.

## Done when
- The dashboard lists ranked targets and the detail view explains *why* each was flagged (parts + hot files + hits + contacts + CVE route + known bugs), with GitHub deep links at the scanned SHA. Usable on a phone.
- Runs start from the UI with live log + progress, through the proxy.
- From outside: `nmap` shows only 80/443 (and 22 if you kept it); `https://<bare IP>` gets no answer; `https://sift.ytax.cc/api/state` without a session goes to the GitHub login; logging in as any GitHub account other than yTax is refused.
- On the box: `curl -H 'Host: sift.ytax.cc' http://127.0.0.1:7777/api/state` → 403 (no user header); with `X-Sift-User: yTax` → 200; a POST without `X-Sift` or with a foreign `Origin` → 403.
- SSL Labs grade A or better; the token never appears in any response, log line, or page source.
