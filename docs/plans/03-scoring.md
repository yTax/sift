# Plan 03 — Better ranking: same-file pairing, density, dependency impact

Three independent upgrades to `score.go` + `scan.go`. Each stands alone; do them in any order. Pairing is the biggest quality jump for the least code.

---

## 3a. Same-file pairing (do this first)

### What it means, plainly

Right now the scan counts sinks and surfaces across the whole repo and scores them separately. But a dangerous call only matters if *untrusted input can reach it*. The strongest cheap signal that it can is when a **surface** (a place input enters — an HTTP route, a packet handler, an IPC handler) and a **sink** (a dangerous call — exec, file path, SQL) sit in the **same file**. Input entering and something dangerous happening, in the same few hundred lines, is exactly the shape of a real bug. Fifty exec calls in one file and fifty routes in a totally different file is probably nothing; one route and one `exec` in the same handler file is a lead.

So: reward files that contain both. That's "pairing."

### How

`scanZip` already produces `Hits` tagged with `Path` and `Kind` (`surface`/`sink`/`auth`). Post-process them grouped by `Path`:

- A file is **paired** if it has ≥1 surface hit and ≥1 sink hit.
- Even better, reward proximity: if a surface and a sink are within ~40 lines of each other in the same file, weight that higher than merely same-file.

Add to `ScanResult`:
```go
PairedFiles   int      // files with both a surface and a sink
HotFiles      []string // the paired file paths, best first — these are your lead list
PairedWeight  float64  // sum of sink weights that live in paired files (optionally x1.5 when within ~40 lines of a surface)
```

In `computeScore`, add a `pairing` part from `logScale(PairedWeight, …)` and give it a healthy default weight (start around the `sinks` weight). Keep the existing `sinks`/`surface` parts but the ranking will now float "input meets danger in one file" repos to the top. Surface the `HotFiles` list in the repo detail view (plan 8) — it's literally where to start reading.

### Done when
- A repo with a route and an `exec` in the same file outranks a repo with the same raw counts spread across unrelated files. Add a `scanZip` test with two fixtures that have identical totals but different co-location, and assert the paired one scores higher.

---

## 3b. Sink density per 1,000 lines (option)

### Why
Big repos win just by being big — more lines, more raw hits. A density option levels that.

### How
`ScanResult` already sums `Bytes` and `Files`; also count lines scanned (`LinesScanned int`). Add a setting `score_by_density bool`. When on, the `sinks`/`surface` parts use `weighted / (lines/1000)` instead of raw totals (guard against tiny repos with a floor, e.g. treat <500 lines as 500 so a 3-line repo with one sink doesn't shoot to the top). Leave it off by default; expose as a toggle.

### Done when
- With density on, a 50k-line repo with 60 scattered hits ranks below a 2k-line repo with 20 concentrated ones. Covered by a scoring unit test.

---

## 3c. Dependency impact (deps.dev)

### Why
A bug in a package lots of other projects depend on is worth more — bigger blast radius, and it's your route toward a maintainer-role reputation. This also helps separate "popular on GitHub" (stars) from "actually depended upon" (real usage).

### How
Use the **deps.dev HTTP API** (`https://api.deps.dev/v3/...`), no key needed. For a repo you can map to a package (npm name from `package.json`, PyPI from `pyproject`/`setup.py`, Maven coords for Jenkins/Java, Go module path), query its dependent count and/or download signal. Store on `Enrichment`:
```go
Ecosystem    string
PackageName  string
Dependents   int
DownloadsWk  int   // where the ecosystem exposes it
```
Add an `impact` score part from `logScale(Dependents, …)`. Do the lookup in `stageEnrich` only for repos that pass the filters (don't spend API calls on repos you're about to drop). Cache by package name; it changes slowly.

Mapping a repo → package is the fiddly bit: cheapest is to read the manifest you already download during scan (reuse the zipball) and pull the package name from it, rather than guessing from the repo name. Degrade gracefully — no mapping just means no impact part (leave it absent, like an unscanned repo).

### Done when
- A repo that maps to a widely-depended-on package scores higher, all else equal.
- No package mapping → `impact` part simply absent, score still computed, marked nothing-special. Covered by a test with a mocked deps.dev response (reuse the mock pattern from plan 2).
