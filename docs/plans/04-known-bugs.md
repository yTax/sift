# Plan 04 — Known-bug check + variant hunting

Two features that both revolve around existing advisories. 4a stops you wasting time; 4b is the expert move that finds new bugs fast.

---

## 4a. Known-bug check (do this first — it's cheap and saves you hours)

### Why
Before digging into a repo, know what's already been found. Two sources:
- **OSV** (`https://api.osv.dev/v1/query`, POST, no key) — returns known advisories for a package or a commit. Query by the package name/ecosystem you mapped in plan 3c, or by commit.
- **The repo's own open issues/PRs** — someone may have an unfixed security report open already (searching titles/labels for `security`, `vulnerability`, `CVE`, `XSS`, `RCE`, etc.). The GraphQL enrichment already pulls recent issues; extend it, or do a REST issue search.

### How
In `stageEnrich`, for passing repos, add to `Enrichment`:
```go
KnownAdvisories int       // from OSV
KnownRefs       []string  // GHSA/CVE ids
OpenSecurityIssues int    // open issues that look security-related
```
This is **information, not a filter** — don't auto-drop repos with known bugs (a repo with one old CVE often has siblings). Surface it on the repo card so you can judge: "already has 3 CVEs, 1 open security issue" tells you whether it's picked clean or freshly interesting. Optionally add a soft score nudge, but default to just displaying it.

### Done when
- Repo cards show known advisory count + ids and any open security-ish issues.
- OSV lookups are cached by package (slow-changing) and only run for passing repos.
- Mocked OSV response covered by a test.

---

## 4b. Variant hunting from fix commits

### Why
This is the technique real researchers use: take a *known* fixed bug, look at exactly what the patch changed, then find other projects that still have the pre-fix pattern. You're not hunting blind — you're copying a proven bug across a scene. Developers make the same mistake in sibling projects constantly.

### How
This is a distinct mode, not part of the normal run. New command/flow:

1. **Input:** an advisory or a fix commit (a GHSA id, or an `owner/repo@sha`). From a GHSA, resolve the fixing commit(s).
2. **Pull the diff** of the fix commit (`/repos/{o}/{r}/commits/{sha}` gives files + patches). The *removed* lines are the vulnerable pattern.
3. **Turn the removed lines into a search.** Two tiers:
   - cheap: extract a distinctive literal/identifier from the removed code and feed it to GitHub **code search** (`/search/code`) across the scene's language — fast, finds copy-paste.
   - better: generate a Semgrep pattern from the diff (ties into plan 7) and run it over the repos already in your DB.
4. **Emit candidates** as repos (same `Repo` shape, a `variant-of:GHSA-xxxx` tag in `Categories` or a note) so they flow into the normal enrich→scan→score pipeline and show up ranked.

Start with the cheap tier (code search on a distinctive token from the diff). It's most of the value for a fraction of the work. The Semgrep tier can come after plan 7.

GitHub code search needs auth and has its own rate limits (and only indexes default branches) — reuse the `HTTP` client's limiter.

### Files
- New `variants.go` — diff fetch, token extraction, code-search fan-out, candidate emission.
- A CLI subcommand (plan 5): `sift variant GHSA-xxxx-xxxx-xxxx` or `sift variant owner/repo@sha`.

### Done when
- Given a real fix commit, sift extracts the changed pattern, finds other repos containing the pre-fix shape, and drops them into the DB as scored candidates tagged with the source advisory.
- Rate limits respected; dedupes against repos already present.
