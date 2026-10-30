# Plan 15 — Who uses it, and will it become a CVE

## Why

The ranking answers "is there probably a bug". Two questions decide whether a bug is worth your evening: how many people run this code (impact, and how much the CVE means on a CV), and whether a report will actually turn into a CVE ID. Both are cheap to estimate and neither is in the score yet.

## A. Impact: "used by"

Sources, all free and keyless:
- **deps.dev** (`api.deps.dev/v3`): for npm, PyPI, Go, Maven, Cargo packages, `GetPackage` → versions, and `GetVersion` → `dependentCount` (direct + indirect dependents). Map repo → package through the package's `links`/repo URL, or through the manifest name found during the scan (`package.json` name, `pyproject.toml` name, `go.mod` module).
- **npm downloads** (`api.npmjs.org/downloads/point/last-week/<pkg>`), **PyPI** (`pypistats.org/api/packages/<pkg>/recent`).
- **WordPress active installs** and **Jenkins installs**: already collected.

Store `Impact{Dependents, Downloads, Installs, Source}` on the repo, refreshed with enrichment. Add a list sort **"Used by"** and an `impact` score part (log scale, like stars). Show it on the repo page ("312 packages depend on this, 48k downloads/week").

## B. Reportability: "CVE-ready"

A 0–10 signal from things already partly collected:
- Private vulnerability reporting on (best: GitHub assigns the CVE) / published advisories before / SECURITY.md.
- A CNA on the path: WordPress (Wordfence, Patchstack, WPScan), Jenkins; these handle the maintainer and assign fast.
- Maintainer responsiveness: median time to first maintainer reply on recent issues (`maintainer_last_reply` is a start; add the median).
- Release cadence: a release in the last 6 months means a fix will ship and the advisory has a version range.
- Penalties: archived soon, single-commit bursts, "not maintained" in the README.

Show it as a chip and a filter ("CVE-ready only"). This is `cve_path` grown up; fold `cve_path` into it rather than keeping two.

## Done when
- The list sorts by "Used by", and a repo whose package has hundreds of dependents shows that number with its source.
- "CVE-ready only" keeps the repos where a report has a clear, fast route to a CVE, and the reason is spelled out on the repo page.
