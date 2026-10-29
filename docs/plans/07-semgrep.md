# Plan 07 — Semgrep taint pass on the top N

## Why

The scanner greps for sinks with regex. Regex can't tell whether untrusted input *actually reaches* a sink — it just sees the sink. Semgrep's taint mode can follow data flow from source to sink, which is the difference between "this file has an `exec`" and "user input flows into this `exec`." Running it on everything would be slow; running it on just your top N confirmed-interesting repos is cheap and cuts false leads before you open them.

This is an **optional enrichment on the top of the ranked list**, not part of every scan. It needs the `semgrep` binary installed; degrade gracefully when it's absent.

## Approach

Semgrep has no Go SDK — it's an external CLI you shell out to and whose JSON you parse.

1. **Detect it:** `exec.LookPath("semgrep")`. If missing, skip with a one-line log (don't error). Document the install (`pipx install semgrep`) in the README.
2. **Pick targets:** the top N passing repos by score (default N=10, a setting). Reuse the zipball you already download in `stageScan` — extract to a temp dir instead of (or in addition to) streaming, so semgrep has files to walk.
3. **Rules:** start with the registry's taint rulesets for the repo's language (`--config p/<lang>` / `p/security-audit`), plus any local rules under a `semgrep/` dir (this is also where plan 4b's generated variant rules land). Run `semgrep --json --quiet --timeout=… --max-target-bytes=…`.
4. **Parse** the JSON results into a new `Enrichment.TaintFindings []TaintFinding` (`{Path, Line, RuleID, Message, Severity}`). Add a score part `taint` (presence and count of taint findings), weighted modestly — it refines the order of the already-high repos rather than dominating.
5. **Surface** the findings on the repo card and in Discord alerts: "Semgrep: 2 taint paths — src/handler.js:42 (user input → exec)." These are the strongest leads of all.

Run this as its own phase/command so it's opt-in and doesn't slow normal runs:
```
sift taint [N]      # run semgrep over the top N, attach findings
```
and a setting to auto-run it at the end of a normal run (default off).

Guardrails: hard timeout per repo, cap target size, run with `--metrics=off`, and sandbox the temp dir (treat the downloaded code as untrusted — don't run anything from inside it, only point semgrep at it).

### Extraction is the risky part — do it carefully
Today's scanner never extracts anything (it reads zip entries in memory), so it can't be zip-slipped. This plan *does* extract, so it reintroduces that bug class — in a tool built to find it. Rules for the extractor (`extractZip(zipPath, dest string, maxBytes int64)` in `taint.go`):
- Clean every entry name; reject absolute paths, drive letters, and anything whose cleaned path escapes `dest` (`filepath.Rel(dest, target)` starting with `..`). On Go 1.24+ you can open `dest` with `os.OpenRoot` and create files through the `*os.Root`, which refuses escapes for you — prefer that.
- Skip symlinks and any non-regular entry (check `f.Mode()`); never follow links.
- Enforce the same total-size and per-file caps as the scanner while copying (decompressed size, not the header's claimed size — zip bombs lie), and cap the entry count.
- Create files `0o600`, dirs `0o700`, under a fresh `os.MkdirTemp` inside `data/tmp`, and `RemoveAll` it in a `defer`.
- Tests: a fixture zip with `../../evil`, `/abs`, a symlink entry, and an oversized entry — assert none lands outside `dest` and the oversized one aborts.

### Expectations and platform notes
- **Semgrep CE taint is mostly intra-file / intra-procedural.** It catches `req.query.x → exec(...)` in one handler, not input that crosses several files or framework magic. Treat findings as strong leads and "no findings" as "not proven safe". Cross-file taint is a paid Semgrep feature; don't design around it.
- **Windows:** native Semgrep on Windows is newer and less reliable than Linux. Expect to run this on the Oracle box or under WSL; on Windows the `LookPath` miss just means "skip", which is fine.
- Registry configs (`p/...`) need network on each run; cache them by saving the ruleset YAML from the registry into `semgrep/cache/` once and pointing `--config` at the local files, so runs are reproducible and work offline.

## Files
- `taint.go` — detect, extract, invoke semgrep, parse JSON, attach findings.
- `cmd/sift` — the `taint` subcommand.
- `config.go` — `semgrep_top_n`, `semgrep_auto`, optional extra config paths.

## Done when
- With semgrep installed, `sift taint 10` attaches taint findings to the top 10 and nudges their order; findings show on the card and in alerts.
- Without semgrep installed, it logs one line and does nothing else.
- A per-repo timeout stops one pathological repo from hanging the pass.
