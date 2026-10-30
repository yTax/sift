# sift — roadmap

sift finds open-source projects worth auditing for real vulnerabilities. It runs a funnel:

```
search (GitHub / WordPress / Jenkins)  →  enrich (metadata, contacts)
   →  filter (drop the dead/unreachable)  →  scan (grep the code for sinks)
   →  score + rank  →  you dig into the top 20–30
```

The backend for all of that already works (`app.go`, `github.go`, `scan.go`, `score.go`, `sources.go`, `store.go`, `server.go`, plus `defaults/dorks` and `defaults/sinks`). This folder is the plan for everything on top of it.

Each file in `docs/plans/` is one self-contained build unit: context, goal, approach, the files it touches, which libraries to use, and how to know it's done. Build them roughly in the order below — later phases lean on earlier ones.

## Phases

| # | Plan | Why it's here | Depends on |
|---|------|---------------|------------|
| 1 | [`01-storage.md`](docs/plans/01-storage.md) | Move state from one big JSON file to SQLite before it grows to tens of MB | — |
| 2 | [`02-testing.md`](docs/plans/02-testing.md) | A mock GitHub so the whole pipeline is testable offline (+ base-URL setting, which also unlocks GitHub Enterprise) | — |
| 3 | [`03-scoring.md`](docs/plans/03-scoring.md) | Same-file pairing, sink-density, and dependency impact — the cheapest wins in ranking quality | 1 |
| 4 | [`04-known-bugs.md`](docs/plans/04-known-bugs.md) | Check OSV/GHSA and open issues so you don't hunt a bug someone already found; variant-hunt from fix commits, by hand (4b) and as a daily feed (4c) | 1 |
| 5 | [`05-cli.md`](docs/plans/05-cli.md) | Headless `sift` commands so it runs from cron on the Oracle box | 1 |
| 6 | [`06-notifications.md`](docs/plans/06-notifications.md) | Discord webhook + bot + watch mode (re-scan shortlisted repos when sink files change) | 1, 5 |
| 7 | [`07-semgrep.md`](docs/plans/07-semgrep.md) | Optional taint pass on the top N — confirms input actually reaches a sink; CodeQL on the very top later (7b) | 3 |
| 8 | [`08-web-dashboard.md`](docs/plans/08-web-dashboard.md) | The dashboard, and hosting it on Oracle behind auth | 1, 3, 4 |
| 9 | [`09-release.md`](docs/plans/09-release.md) | goreleaser + GitHub Actions for Windows/Linux/ARM builds | — |
| 10 | [`10-fresh-surface.md`](docs/plans/10-fresh-surface.md) | Make "a sink appeared recently" a sortable/filterable signal — fresh code has the least competition | 1, 6 |
| 11 | [`11-bounty-scope.md`](docs/plans/11-bounty-scope.md) | Tag candidates that are likely in a paying program so you can pick "fast CVE" vs "paid" per session | 1 |
| 12 | [`12-checkers.md`](docs/plans/12-checkers.md) | Bug checkers per bug class (prefix containment, tool path → fs, shell from input, SSRF, route without auth…) — sift points at lines, not just repos | 3a |
| 13 | [`13-learned-ranking.md`](docs/plans/13-learned-ranking.md) | Suggest score weights from your real/dud marks (logistic regression in plain Go, suggest-then-apply) | 8a |

### Build order

The numbers above are IDs, not the order to build in. The goal is a tool that finds bugs with as little manual reading as possible, without paying for an LLM.

Done so far:
- **First real run** (MCP scene, 1,443 repos). It exposed slow enrich (fixed: batches run in parallel) and a ranking that pinned at 100 (fixed: wider caps, history curve).
- **3a (pairing)**, scored as `pairing`; hot files show on the repo page.
- **3d (`cve_path`)**.
- **8a, basic UI**: ranked list, repo page, run panel, real/dud marks. The scenes/settings screen is still to do.
- **4a (known bugs)**, minus OSV (needs 3c's package names): published advisories and security-looking open issues.
- **12 (checkers), layers 1 and 2**: eight checkers for JS/TS, Python, Go and PHP, tightened against real repos; Semgrep confirms findings on the top 30 (plan 7, `taint.go`).
- **Scan speed**: literal prefilter (`litfilter.go`), concurrency from the CPU count, `scanEngine` versioning instead of forced rescans.
- **4b (variants), cheap tier**: GHSA or fix commit → code searches → candidates in the `variants` scene.
- **1 (SQLite)**, pulled forward: rewriting a 35 MB `state.json` during scans was filling the disk. State lives in `data/sift.db`; a save writes only the repos that changed.

Next, in order:
1. **Review the checker findings** from the first full run; every false positive becomes a fixture and a fix.
2. **4c (variant feed)**: the daily advisory feed on top of 4b.
3. **5 (CLI) → 8b (hosting on Oracle) → 6 (Discord, watch)**: runs while you're out and pings your phone with confirmed findings, not just repos. Deployment details get settled with the real server config at that point.
4. **7b (CodeQL)** on the Oracle box, and **13 (learned ranking)** once there are enough marks.
6. The rest as they become useful: 2, 3b/3c, 9, 10, 11, the settings screen.

**Ruled out:** running a target app and firing payloads at it (dynamic exploit testing). sift never runs downloaded code. **Maybe later:** a free local LLM on the Oracle box for first-pass triage. No paid API.

## Conventions (read before building anything)

**Don't reinvent the wheel.** Use well-known libraries where they pull their weight; keep the stdlib where it's already enough. The specific picks per phase:

- **SQLite:** `modernc.org/sqlite` (pure Go — builds with `CGO_ENABLED=0`, so it still cross-compiles cleanly to the Oracle ARM box and to Windows). Drive it through `database/sql`; add `github.com/jmoiron/sqlx` only if the scanning boilerplate gets annoying. **Do not** use `mattn/go-sqlite3` — it needs cgo and breaks the cross-compile.
- **CLI:** `github.com/spf13/cobra`.
- **Discord bot:** `github.com/bwmarrin/discordgo`. Webhooks are just an HTTP POST — no library.
- **Semgrep, deps.dev, OSV:** no Go SDK needed. Semgrep is an external binary you shell out to and parse; deps.dev and OSV are plain HTTP + JSON (`api.deps.dev`, `api.osv.dev`).
- **Web frontend:** keep the existing JSON API; keep the UI dependency-light (see plan 8 for the recommendation and rationale). Everything ships embedded in the binary via `go:embed` — no separate web server to deploy.
- **Reverse proxy / TLS on Oracle:** nginx + certbot (Let's Encrypt) for a `ytax.cc` subdomain, with `oauth2-proxy` as the login gate. See plan 8b.

**Keep the single binary.** sift is one self-contained executable with `web/` and `defaults/` embedded. Nothing in these plans should require a second service, a container, or a cloud database. SQLite is a file next to the binary. (nginx and oauth2-proxy on the VPS are deployment infrastructure in front of sift, not part of it — sift still runs fine on its own on localhost.)

**The token never leaves the machine.** It lives in `data/settings.json` (git-ignored) and is already masked out of the `/api/state` response. Anything new — the dashboard, the Discord bot, logs — must keep it that way. The web dashboard becomes internet-facing in plan 8, so it gets authentication *before* it's exposed. On the server the token comes from an env file, not the UI, and it's a fine-grained token that can only read public repos (plan 8b) — so even a leak is close to harmless.

**Treat downloaded code as hostile.** sift pulls arbitrary repos. Scanning reads zips in memory and never extracts or executes anything; anything that does extract (plan 7) must reject `..`/absolute paths and symlinks, and nothing ever runs code from a scanned repo.

**Package layout.** The code is currently one flat `main` package. That's fine now, but cobra (plan 5), the bot, and the web layer will make it messy. Plan 5 includes an optional, low-risk restructure into `internal/` packages + `cmd/sift`. Do it when you get there, not before.

**Testing.** Every phase ships with tests. After plan 2 there's a mock GitHub, so the search→enrich→scan path can be tested end to end with no network and no token. Keep the existing `sift_test.go` style: table-driven, real fixtures, and at least one test that proves a check actually fires (not just that the happy path passes).

## Current data model (so the plans make sense)

- **`Repo`** — one candidate. Key is `gh:owner/repo`, `wp:slug`, or `jk:id`. Holds `Enriched`, `Contacts`, `Scan`, `Score`, `Filter`, plus `Status` (`new`→`shortlist`→`digging`→`reported`→`skipped`) and `Notes`.
- **`Enrichment`** — metadata: push date, releases/tags, PVR flag, advisory count, maintainer-reply recency, topics, license.
- **`ScanResult`** — `SurfaceHits` / `SinkHits` / `AuthHits`, `WeightedSinks`, `ByClass`, and the `Hits` themselves (`Path`, `Line`, `Kind`, `Label`, `Class`, `Weight`, `Snippet`).
- **`Score`** — `Total` (0–100), `Parts` (sinks, surface, auth, history, responsiveness, freshness, contact, cve_path), `Partial` (true when the code wasn't scanned).
- **`Repo.CVEPath`** — how a finding would become a CVE: `github-pvr`, `github-advisory`, `security-policy`, `wordpress-cna`, `jenkins-cna`, `mitre`, `none`. Scored when `score_cve_path` is on (default).

These persist in `data/sift.db` (SQLite, one JSON row per repo; see plan 1). An old `data/state.json` is imported once and kept as `state.json.imported`.
