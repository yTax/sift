# Plan 09 — Release builds (goreleaser + GitHub Actions)

## Why

You run sift on at least the Oracle ARM box and probably a Windows/Linux desktop. Hand-building for each is tedious. goreleaser cross-compiles everything from one tag push and attaches the binaries to a GitHub release.

This is independent of every other phase — it can be done any time — but it's most useful **after** plan 1, because the pure-Go SQLite choice (`modernc.org/sqlite`) is what lets `CGO_ENABLED=0` cross-compile to ARM64 and Windows without a C toolchain. Don't switch to a cgo SQLite driver or this phase gets painful.

## Targets
- `linux/amd64`, `linux/arm64` (Oracle Ampere), `windows/amd64`, and `darwin/arm64` if you want it.

## Approach

`.goreleaser.yaml`:
- `builds:` one entry, `env: [CGO_ENABLED=0]`, the goos/goarch matrix above, ldflags stamping `version` (currently the `version` const in `main.go` — move it to a `var` set via `-X main.version=…` so releases carry the tag).
- `archives:` tar.gz for unix, zip for windows, **including** the `defaults/` tree so a fresh install has dorks/sinks (note: they're already embedded in the binary via `go:embed` and restored on first run, so the archive copy is just convenience — fine either way).
- `checksum:` + optional `signs:` (cosign) if you want signed releases.

GitHub Actions `.github/workflows/release.yml`:
- trigger on `push: tags: ['v*']`;
- `actions/setup-go`, then `goreleaser/goreleaser-action` with `GITHUB_TOKEN`.
- A separate `ci.yml` on push/PR that runs `go test ./...`, `go vet`, and `gofmt -l` (fail if anything's unformatted) — cheap insurance given the regex-heavy sink profiles.

## Files
- `.goreleaser.yaml`
- `.github/workflows/release.yml`, `.github/workflows/ci.yml`
- `main.go` — `version` from const to ldflags-set var.

## Done when
- `git tag v0.2.0 && git push --tags` produces a GitHub release with linux amd64/arm64 + windows binaries, each running `sift` with the right version string.
- CI runs tests + vet + gofmt on every push/PR and goes red when they fail.
