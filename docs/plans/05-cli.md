# Plan 05 — CLI mode

## Why

Right now sift only runs as a local web server that opens a browser. To run it from cron on the Oracle box — and to drive it from the Discord bot and watch mode (plan 6) — it needs headless commands that do a run and print/export results without a UI.

## Library

`github.com/spf13/cobra`.

## Optional (recommended) restructure

cobra wants a `cmd/` layout, and the flat `main` package is going to get crowded with the bot, web, and CLI all landing. A low-risk move:

```
cmd/sift/main.go          # cobra root, wires everything
internal/sift/            # everything that's in package main today
  app.go store.go github.go scan.go score.go sources.go dorks.go contacts.go config.go server.go
```

Mechanical change — move files, rename `package main` → `package sift`, export the few symbols `cmd/` needs (`NewApp`, `App.StartRun`, `App.Routes`, …). Do it as its own commit before adding commands so the diff is reviewable. If you'd rather not, cobra works in a flat package too; it's just tidier this way.

## Commands

```
sift serve                 # current behaviour: start the web server (default when no subcommand, keeps today's UX)
sift run [--scene …] [--stages search,enrich,scan] [--force]
                           # one full pipeline pass, headless; progress to stderr, summary to stdout
sift top [N] [--scene …] [--json|--table]
                           # print the current top N passing repos (no run) — default 30
sift export [--scope passing|all|shortlist] [--format csv|json] [-o file]
                           # same data as the web /api/export, from the terminal
sift scenes                # list categories and their enabled/contact/prescore flags
sift variant <GHSA|owner/repo@sha>   # plan 4b
sift watch [--scene …] [--interval 6h]   # plan 6
```

Flags that mirror existing `RunOpts` (`Stages`, `Categories`, `Force`). Reuse `App`, `StartRun`/`run`, `Rescore`, and the export logic in `server.go` — factor the CSV/JSON writer out of the HTTP handler so both the handler and `sift export` call it.

Config/token resolution stays as-is (`TokenAndSource`: env wins over `settings.json`). `--dir` and the base-folder resolution from `main.go` carry over as a persistent flag.

For `sift run` on cron, exit non-zero if the run errored, and keep stdout to the summary line (counts) so it's greppable; detailed progress goes to stderr/log.

## Files
- `cmd/sift/main.go` (+ the `internal/sift` move if you take it).
- `export.go` — extracted writer shared by HTTP + CLI.
- `go.mod` — add cobra.

## Done when
- `sift run --scene mcp` does a full pass with no browser and prints a summary; exit code reflects success.
- `sift top 20 --json` prints the ranked list offline (reads the DB, no run).
- `sift serve` still behaves exactly like today's default.
- A cron line like `0 */6 * * * sift run && sift export -o /srv/sift/latest.csv` works.
