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

## Files
- `taint.go` — detect, extract, invoke semgrep, parse JSON, attach findings.
- `cmd/sift` — the `taint` subcommand.
- `config.go` — `semgrep_top_n`, `semgrep_auto`, optional extra config paths.

## Done when
- With semgrep installed, `sift taint 10` attaches taint findings to the top 10 and nudges their order; findings show on the card and in alerts.
- Without semgrep installed, it logs one line and does nothing else.
- A per-repo timeout stops one pathological repo from hanging the pass.
