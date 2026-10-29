# Plan 02 — Mock GitHub + base-URL setting

## Why

The GitHub half of the pipeline (REST search, GraphQL enrichment, zipball download) is the one part that's never been run against real results, because the sandbox it was built in blocked GitHub. A mock server fixes two things at once: the pipeline becomes testable offline with no token, and a configurable base URL also makes the tool work against **GitHub Enterprise**.

This is deliberately small. It is *not* a standalone binary or a separate service — just a configurable base URL plus an `httptest.Server` in the tests. Don't overbuild it.

## Approach

**1. Make the GitHub base URL a field, not a constant.**

In `github.go` the URLs are hardcoded (`https://api.github.com/...`, `https://codeload.github.com/...`). Add to the `HTTP` struct:

```go
apiBase  string // default "https://api.github.com"
```

Build every GitHub URL from it (`h.apiBase + "/search/repositories?..."`, `h.apiBase + "/graphql"`, `h.apiBase + "/repos/" + full + "/zipball/" + ref`, etc.). `newHTTP` takes the base (fall back to the default when empty). Add an optional `github_api_base` to `Settings` so Enterprise users can point it at `https://ghe.example.com/api/v3`. The `ghResource` host check keys off the base host, not a literal `api.github.com`.

Leave WordPress (`api.wordpress.org`) and Jenkins (`updates.jenkins.io`) as-is for now; they already worked live. If you want them mockable too, give them the same treatment, but it's optional.

**2. A fixture-backed mock in tests.**

Use `net/http/httptest`. One handler that routes on path:
- `GET /search/repositories` → return a canned `ghSearchResp` (a couple of pages, including one query that trips the `>1000` auto-split so that path gets covered).
- `POST /graphql` → parse the aliased query, return a `data` object with an `r0`, `r1`… per requested repo, matching the `gqlRepo` shape (README/SECURITY blobs, owner social accounts, issue/PR comment nodes with author associations so maintainer-reply detection is exercised).
- `GET /repos/{o}/{r}/private-vulnerability-reporting` → `{"enabled": true/false}` or 404.
- `GET /repos/{o}/{r}/security-advisories` → a small array.
- `GET /repos/{o}/{r}/zipball/{ref}` → serve a real `.zip` built on the fly (the `TestScanZip` test already builds zips — reuse that helper) so the download+scan path runs against the mock too.

Point the client at `srv.URL` via the new base field and run `a.run(...)` or the individual stages against it.

Keep fixtures as plain `.json`/`.go` literals under `testdata/`. If recorded real responses are ever wanted, `github.com/dnaeon/go-vcr` can record/replay cassettes — but hand-written fixtures are lighter and enough here.

## Files

- `github.go` — `apiBase` field, URL construction, `newHTTP` signature.
- `config.go` — `GitHubAPIBase` setting (optional, defaults empty).
- `app.go` — pass the setting through to `newHTTP`.
- New `github_mock_test.go` + `testdata/` — the mock and fixtures.

## Done when

- `newHTTP("", logf)` still hits real github.com (no behaviour change for users).
- A full `search → enrich → scan` run against the `httptest` mock produces scored repos with zero network calls and no token.
- Setting `github_api_base` routes all GitHub calls elsewhere (verified by the mock test).
- The auto-split-over-1000 branch and the maintainer-reply-recency branch are both hit by a test.
