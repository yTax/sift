# Plan 01 — SQLite storage

**Status:** built (`store.go`), the minimal shape below. The repo map stays in memory; a save marshals each repo, compares a hash with what was last written and upserts only the changed rows in one transaction (deleted repos and capped-off runs are removed). Migrations are an ordered slice in `store.go`. `modernc.org/sqlite` is pinned at v1.46.1, the last release that builds with Go 1.24; newer ones raise the `go` line in `go.mod`.

## Why

`store.go` keeps every repo in a map and rewrites the whole thing to `data/state.json` every ~2 seconds during a run (`saver()` + `markDirty()`). Once scan hits and snippets pile up, that file grows to tens of MB and every save re-serialises all of it. SQLite fixes that: incremental writes, real queries for the dashboard's filters, and no "rewrite the world" on every change.

Keep `data/settings.json` as a plain JSON file — it's small and nice to hand-edit. Only the repo/run state moves.

## Library

`modernc.org/sqlite` through `database/sql`. Pure Go, so `CGO_ENABLED=0` cross-compiles stay intact (this matters for the Oracle ARM box and Windows builds). Add `github.com/jmoiron/sqlx` if row scanning gets tedious — optional.

## Approach

Keep the `Store` type and its method names (`With`, `Read`, `Get`, `GetJSON`, `AddRun`, `FinishRun`, `Runs`, `SaveNow`) so callers in `app.go` and `server.go` don't all change at once. Swap the guts from map+JSON to SQLite.

Two workable shapes — pick based on how much you want to touch callers:

- **Minimal:** store each `Repo` as a row of `(key TEXT PRIMARY KEY, source TEXT, status TEXT, score REAL, json TEXT)` where `json` is the marshalled `Repo`. You get incremental per-repo writes immediately and can still filter/sort on the promoted columns (`source`, `status`, `score`) for the dashboard. Least churn.
- **Fuller:** promote the fields the dashboard filters on into real columns (language, popularity, pushed_at, advisories, sink_hits, passing, first_seen). More migration work, but the dashboard (plan 8) can paginate and filter in SQL instead of loading everything into memory.

Recommended: start minimal (json blob + promoted `source`/`status`/`score`/`passing`/`updated_at`), add columns later as the dashboard needs them. The blob keeps the `Repo` struct as the source of truth so you're not maintaining a parallel schema by hand.

Schema sketch:

```sql
CREATE TABLE repos (
  key        TEXT PRIMARY KEY,
  source     TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'new',
  score      REAL,
  passing    INTEGER NOT NULL DEFAULT 0,  -- Filter.Pass as 0/1
  updated_at TEXT NOT NULL,
  json       TEXT NOT NULL                -- the full Repo
);
CREATE INDEX repos_score ON repos(passing, score DESC);
CREATE INDEX repos_status ON repos(status);

CREATE TABLE runs (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  started  TEXT, finished TEXT,
  json     TEXT NOT NULL
);

CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);  -- schema_version, etc.
```

Connection setup that matters:
- Open with `?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)`. WAL lets the dashboard read while a run writes.
- `db.SetMaxOpenConns(1)` is the easy, safe default for a single-user tool and sidesteps most "database is locked" pain. Revisit only if the dashboard feels slow.
- Wrap the burst of writes in `stageSearch`/`stageEnrich`/`stageScan` in transactions (one tx per batch) instead of per-row autocommit — that's where the speed comes from.

Migrations: a tiny embedded runner is enough — a `meta.schema_version` row and an ordered slice of `CREATE`/`ALTER` strings in `migrations.go`, applied in a transaction on open. No need for `golang-migrate` yet.

## One-time import

On first start, if `data/state.json` exists and the DB is empty, read it and insert every repo, then rename the old file to `state.json.imported` so it's not re-read. This is the only place the old format is still parsed; keep the `stateFile` struct around just for it.

## Files

- New `storage_sqlite.go` (or rename `store.go`) — the SQLite-backed `Store`.
- New `migrations.go` — schema + version runner.
- `app.go`, `server.go` — unchanged if method signatures hold. `GetJSON`/`hRepos` already encode via JSON, which fits the blob model.
- `main.go` / `NewApp` — open the DB at `data/sift.db` instead of (or alongside) the JSON store.
- `go.mod` — add `modernc.org/sqlite`.

## Done when

- A fresh run writes to `data/sift.db`; no `state.json` is created going forward.
- An existing `data/state.json` is imported once on upgrade and then left alone.
- A run of a few hundred repos doesn't rewrite the entire dataset on every change (check with `strace`/file mtime, or just reason about the tx code).
- The dashboard/API reads a repo while a run is writing without "database is locked" (WAL + busy_timeout).
- Tests: open an in-memory or temp-file DB, insert/read/update a repo, run the state.json importer against a fixture, and confirm a second `NewApp` on the same DB sees the data.
