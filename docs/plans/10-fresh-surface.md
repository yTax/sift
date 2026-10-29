# Plan 10 — Fresh-attack-surface signal

## Why

A sink that has existed for three years has been seen by everyone; a sink that *appeared last week* probably hasn't. Fresh code is where the uncontested bugs are. The current score treats a repo's danger as static — this plan makes "how recently did the attack surface change" a first-class signal you can **sort and filter on**, not just a number folded into the total.

Key design decision (per request): this is a **sortable dimension**, not something baked silently into one score. You choose, per session, whether you want "highest score" or "freshest surface." A low-scoring repo that just grew a new sink file might be the best use of your time precisely because nobody's looked yet.

## The signal

Three freshness levels, cheapest first:

1. **Release freshness (WordPress / Jenkins)** — already in hand. WordPress `last_updated` and Jenkins `releaseTimestamp` are fetched today; a new release = new code to look at. Just needs exposing as a sort key.
2. **Repo push freshness (GitHub)** — `Enriched.PushedAt` already exists; already used in the `freshness` score part. Expose as its own sort key too.
3. **Sink-file freshness (the valuable one, GitHub)** — did a *sink-bearing* file get added or changed recently? This is the real "fresh attack surface" signal and it's new work. Build it on top of watch mode (plan 6b), which already diffs `old...new` commit ranges and checks changed paths against sink-profile extensions. When a changed/added file matches, record it.

## Data model

Add to `Enrichment` (or a small sibling struct):

```go
SurfaceChangedAt time.Time   // most recent time a sink-bearing file was added/modified
NewSinkFiles     []string    // sink files added/changed in the last window
SurfaceFirstSeen map[string]time.Time  // per hot file, when sift first saw a sink in it
```

Populate it two ways:
- **On first scan:** `SurfaceFirstSeen` for each hot file = now (we can't know true history cheaply; treat first-seen-by-sift as the baseline). Optionally, for the top repos only, pull the file's last-commit date via `/repos/{o}/{r}/commits?path=<file>&per_page=1` to get the *real* age — do this sparingly, it's one call per file.
- **On each watch tick:** when the commit diff touches a sink file, set `SurfaceChangedAt = now`, append to `NewSinkFiles`, and fire the watch alert (plan 6b already does the alert; this just records the timestamps that make it sortable afterwards).

## Sorting & filtering (the point)

- **API:** add a `sort` param to `/api/repos` (`score` default, plus `surface_changed`, `pushed`, `released`, `first_seen`) and a `fresh_within=<days>` filter. With SQLite (plan 1) these are `ORDER BY` / `WHERE` on promoted columns — promote `surface_changed_at` and `pushed_at` to real columns so it's a cheap query.
- **CLI:** `sift top --sort surface --fresh 14` → freshest attack surface in the last 14 days.
- **Dashboard:** a sort dropdown and a "changed in last N days" filter on the targets table. A small "🆕 new sink file" badge on rows where `SurfaceChangedAt` is recent, linking to the changed file at that SHA.

## Optional score nudge

Keep it optional and off by default, because it would fight the sort. If wanted, a small `surface_freshness` score part (decays over ~30 days) — but the primary interface is the sort, exactly so a fresh low-scorer can still surface when you ask for it.

## Files
- `watch.go` (plan 6) — record `SurfaceChangedAt` / `NewSinkFiles` when a diff touches a sink file.
- `scan.go` — set `SurfaceFirstSeen` on first scan.
- `github.go` — optional per-file last-commit-date lookup for top repos.
- `storage` (plan 1) — promote `surface_changed_at`, `pushed_at` to columns + indexes.
- `server.go` / `export.go` / `cmd` — `sort` + `fresh_within` params.

## Done when
- `sift top --sort surface --fresh 14` lists repos whose sink files changed in the last two weeks, newest first, regardless of their total score.
- The dashboard can sort the table by freshest attack surface and filter to a recent window, with a badge on freshly-changed repos.
- A watch tick that touches a sink file updates the repo's `SurfaceChangedAt` (covered by a test using the compare-endpoint mock from plan 2).
