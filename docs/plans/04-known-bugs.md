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

**Status:** cheap tier built (`variants.go`, "Hunt variants" in the run panel, `POST /api/variant` for the preview). Input is a GHSA id, fix commit/PR URL or `owner/repo@sha`. It reads the removed lines (or, for fixes that only add a check, the unchanged sink lines around them), builds up to three code searches from identifiers the fixed code no longer has, adds a word when a search matches over 1,000 files, and files the matching repos under the `variants` scene tagged `variant-of:<ref>`. The search can be edited before the hunt. Found in testing: most hits are vendored copies in abandoned repos, which the normal filters drop. Not built: the Semgrep tier and searching repos already in the DB.

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

## 4c. Automatic variant feed (after 4b works by hand)

**Status:** built (`feed.go`, "Variant feed" in the run panel, a Settings group). Every half hour sift checks whether a day has passed since the last look; if so it starts a feed run. The run pulls reviewed advisories published since then (a week back the first time) whose CWEs map to a checker class, keeps npm/pip/go/composer ones that link a fix, ranks them (severity, server-side class over XSS, MCP/agent/WordPress/Jenkins packages first) and plans the top ones like a hand hunt. Only fixes that touch a line a checker flags are hunted (`feed_per_day`, default 8); the rest are listed with the reason and a "Hunt by hand" button. Candidates go through enrich → scan → Semgrep as one run. Not built yet: searching repos already in the DB with the fix's checker (step 4, first half), classifying a fix by the guard it added (step 3), Discord alerts (waits on plan 6).

### Why
4b starts from an advisory you pick. The feed picks them for you: every new advisory in the scenes sift watches becomes a variant search on its own, so sift turns up candidates while you're away.

### How
1. **Pull new advisories daily** from the global GitHub advisory database (`GET /advisories?ecosystem=npm|pip|go|maven&published=>{last}&type=reviewed`, plain REST with the existing token). Keep the ones whose package or repo falls in a watched scene (MCP/agent topics, WordPress, Jenkins) and whose CWE is one the checkers know (22, 78, 918, 502, 284/862).
2. **Find the fix commit.** The advisory's `references` usually link it; otherwise skip the advisory. Don't guess.
3. **Classify the fix by what it added**, not only what it removed: a `path.relative`/`Rel` containment check, a switch from `exec` to an argument array, a host allow-list, an auth middleware. Each added guard maps to a plan 12 checker. "Fix added a containment check" means "look for that same handler shape without one".
4. **Search** in two places: the repos already in the DB (run the matching checker over their stored hits, or rescan the hot files), and GitHub code search for a distinctive identifier from the vulnerable code, limited to the scene's language. Same rate-limit and dedupe rules as 4b.
5. **Emit** candidates tagged `variant-of:GHSA-…` so they enter the normal pipeline, and send a Discord alert (plan 6) when a candidate also has a checker finding.

### Done when
- A daily tick with one new path-traversal GHSA in an MCP package produces tagged candidates from both the DB and code search, without running anything from the advisory's repo.
- Advisories without a resolvable fix commit are logged and skipped.
