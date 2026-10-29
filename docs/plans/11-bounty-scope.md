# Plan 11 — Bounty-scope correlation

## Why

Some of these scenes pay and some only give a CVE. Right now sift doesn't know the difference, so you can't choose "fast CVE tonight" vs "paid bug this week." This plan tags each candidate with whether it's in a paying program and roughly what tier, so you can sort and filter by it.

Important honesty up front: a tag means **"this looks in-scope,"** not "guaranteed payout." Programs decide eligibility by their own rules (install thresholds, vulnerability type, in-scope lists) that change over time. So this is a heuristic flag driven by **config you keep current**, not a promise — the UI should say "likely paid" not "paid."

## Sources & how to get them

Scopes shift, so make them **config-driven files** the user updates, with optional auto-refresh where a stable source exists.

### Wordfence (`bounty/wordfence.yaml`)
Wordfence pays for in-scope WordPress plugin/theme vulns, with payout gated on **active installs** and **vulnerability type**, and runs periodic bonus promotions on a published **high-threat list**. Model it as thresholds:

```yaml
program: wordfence
min_installs_by_type:
  rce: 1000
  sqli: 50000
  auth_bypass: 50000
  arbitrary_file_upload: 1000
  # ... the current scope table
high_threat_slugs: []   # paste the current promotion list; optional auto-fetch below
```

A WordPress candidate is flagged "likely paid" when its `active_installs` (already fetched) meets the threshold for a plausible vuln type for that plugin. Since you don't know the vuln type before you find it, flag the **best achievable tier** given its install count (e.g. ≥50k installs → everything qualifies; 1k–50k → only the low-threshold types). Store that as the tier.

Auto-refresh (optional, later): Wordfence Intelligence publishes a vulnerability data feed and the weekly/monthly reports; the high-threat promotion list lives on their blog. Start with manual YAML you refresh occasionally — don't block this feature on scraping.

### Jenkins (`bounty/jenkins.yaml`)
The Jenkins bug bounty covers core, some components, and a **defined list of in-scope plugins**, for a bounded time window.

```yaml
program: jenkins
in_scope_plugin_ids: []   # the current in-scope plugin list
window_ends: 2026-12-31   # bounty runs ~late 2025 to late 2026 — flag expiry
```

A Jenkins candidate is flagged paid when its plugin id is in `in_scope_plugin_ids`. Also surface `window_ends` so you know the paid window is closing (after it, the scene is CVE-only — still worth it, just not paid). This dovetails with the existing `jenkins.only_ids` dork option: you can both *search only* in-scope plugins and *tag* scope.

### GitHub scenes
Mostly CVE-only (no umbrella program), so they get no bounty tag by default — which is itself useful signal (these are your "fast CVE" scene). Leave room in the config format to add a program later (e.g. if you enroll a scene in something).

## Data model

```go
// on Repo
Bounty *BountyScope
type BountyScope struct {
    Program   string  // "wordfence" | "jenkins"
    InScope   bool
    Tier      string  // free-text: "≥50k installs: all types" / "in-scope plugin" / ""
    Note      string  // e.g. "paid window ends 2026-12-31"
}
```

Set it during `stageSearch`/`stageEnrich` by matching against the loaded `bounty/*.yaml`. No network needed for the manual version.

## Sorting & filtering

- **Filter:** `paid only` / `cve only` — the core "what kind of session is this" switch.
- **Sort/group:** group the table by program, or sort paid-first.
- **CLI:** `sift top --paid` and `sift top --cve-only`.
- **Dashboard:** a filter toggle and a badge (`💰 Wordfence · ≥50k` / `💰 Jenkins in-scope`), plus a quiet warning badge when a paid window is near its end.
- **Export:** add a `bounty` column to the CSV so a shortlist carries the paid/CVE call.

Optional, off by default: a small score nudge for paid candidates. Prefer the filter — mixing payout into the score muddies "most likely to have a bug," which should stay the score's only job.

## Files
- New `bounty.go` — load `bounty/*.yaml`, match repos, set `Repo.Bounty`.
- New `defaults/bounty/wordfence.yaml`, `defaults/bounty/jenkins.yaml` — starter configs with today's scope and a comment on where to refresh them.
- `app.go` — apply bounty matching in the pipeline.
- `server.go` / `export.go` / `cmd` — `paid`/`cve-only` filters, badge data, CSV column.

## Done when
- A high-install WordPress plugin and an in-scope Jenkins plugin both show a "likely paid" badge with their tier; a GitHub MCP repo shows none.
- `sift top --paid` lists only flagged candidates; `--cve-only` excludes them.
- The config files are plain YAML the user can edit, and editing them re-tags on the next run with no code change.
- A Jenkins candidate past `window_ends` is flagged as no-longer-paid, not dropped.
- Matching logic covered by a unit test with fixture configs (no network).
