# Plan 08 — Web dashboard + hosting on Oracle

## Why

The JSON API in `server.go` already exists (`/api/state`, `/api/repos`, `/api/repo`, `/api/run`, `/api/events` SSE, `/api/export`, the toggles). What's missing is the actual UI, and a safe way to reach it from anywhere instead of only `localhost` on the machine it runs on. Goal: a dashboard where you see the ranked list, open a repo to see *why* sift flagged it (score parts, hot files, contacts, known bugs, leads), and drive runs — hosted on the Oracle box behind your domain.

## Two parts, in order: build the UI, then expose it safely.

---

## 8a. The dashboard UI

### Recommendation
Keep the existing JSON API and build a small single-page app embedded via `go:embed` (as `web/` is today). Keep the JS footprint light — this is a dense data tool, not a marketing site. Good fits, any of:
- **Vanilla + a tiny reactive lib** (Alpine.js) — least build tooling, drops in over the current `web/index.html`.
- **htmx** — server renders HTML fragments, almost no client JS; fits the SSE/live-run model nicely.
- A small **Preact/Vite** build if you want components — heavier toolchain, only if the UI gets complex.

Pick one; don't mix. All ship embedded in the binary, so hosting stays "one executable."

### Screens
1. **Targets table** — the ranked list. Columns: score, name, scene, language, popularity, last push, advisories, contact kinds, sink/surface/auth counts, status. Sort by score; filter by scene, source, status, language, pass/fail; search. This is `/api/repos` (already sorted by score). Paginate once the DB (plan 1) can do it in SQL.
2. **Repo detail** — the "why flagged" view, the heart of it:
   - score with the **part breakdown** (sinks/surface/auth/history/responsiveness/freshness/contact/pairing/impact/taint) as a bar or radar so you see what drove it;
   - **hot files** (plan 3a) — the lead list, each a deep link to the file on GitHub at the scanned SHA;
   - the actual **hits** grouped by file with line numbers and snippets (already in `ScanResult.Hits`), linking to the line on GitHub;
   - **contacts** (how to report) and **known advisories / open security issues** (plan 4);
   - **filter reasons** when it didn't pass;
   - status control (`shortlist`/`digging`/`reported`/`skipped`) + notes — already in `/api/repo` POST.
3. **Run panel** — kick a run (scene picker, stages, force), live log via the existing SSE `/api/events`, progress bar. The current top bar already has the shape of this.
4. **Scenes/settings** — toggle categories and queries, test a query (`/api/query/test`), edit weights and filters.

### Nice-to-haves (once the basics work)
Saved views (a filter set you name), tags on repos, keyboard triage (`j`/`k` to move, `s` shortlist, `x` skip) — all client-side over the existing endpoints. A disclosure tracker view: repos with status `reported`, report date, and a 90-day countdown (store report date in notes or a new field).

---

## 8b. Hosting on Oracle — safely

### The problem
Today `server.go` is deliberately `localhost`-only (`guard` rejects non-local Host) and the `/api/state` response masks the token. The moment it's internet-facing, it exposes a tool that **holds a GitHub token, can trigger runs, downloads arbitrary repos, and reveals maintainer contacts.** So it does **not** go on the public internet unauthenticated. Two layers:

1. **Keep sift bound to localhost** on the Oracle box (`-addr 127.0.0.1:7777`). Don't expose it directly.
2. **Put Caddy in front**, on the `ytax.cc` subdomain, doing:
   - automatic HTTPS (Caddy gets the cert itself);
   - **authentication** — Caddy `basic_auth`, or better, an auth portal / an allow-listed path. At minimum a strong basic-auth credential. This is the gate.
   - reverse-proxy to `127.0.0.1:7777`.

Then relax sift's own guard just enough to work behind the proxy: accept the proxied Host, trust `X-Forwarded-*` only from localhost, and **keep the `X-Sift` header requirement** (or swap to a proper same-site cookie/CSRF token) so a browser on another site can't drive the API. Keep the token masked in every response — never send it to the browser, and don't add an endpoint that returns it.

Run sift as a **systemd service** (`sift serve`), DB at `/srv/sift/data/sift.db`, restart-on-failure, logs to journald. A `deploy/` dir with the `Caddyfile` snippet and the `.service` unit makes it reproducible. Since the binary is self-contained (plan 1 keeps SQLite as a pure-Go file DB), deploying is: copy the ARM64 binary, copy `dorks/`+`sinks/`, start the unit.

### Settings auth note
The settings screen can set the token. Behind auth that's fine, but consider making the token *read-only from the UI* (set via env/file on the box, shown only as "set from env"). Lower blast radius if the dashboard credential ever leaks.

## Files
- `web/` — the SPA (replacing the placeholder `index.html`), embedded.
- `server.go` — proxy-aware guard, keep token masking, keep CSRF/header check; pagination/filter params on `/api/repos` once SQL-backed.
- `deploy/Caddyfile`, `deploy/sift.service`, and a short `deploy/README.md`.

## Done when
- The dashboard lists ranked targets and the detail view explains *why* each was flagged (parts + hot files + hits + contacts + known bugs), with GitHub deep links at the scanned SHA.
- Runs start from the UI with live log + progress.
- On Oracle: `https://sift.ytax.cc` serves it over TLS, behind auth, with sift itself bound to localhost and the token never sent to the browser.
- A browser tab on another origin cannot drive the API (CSRF/header check holds).
