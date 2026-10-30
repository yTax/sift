# Plan 16 — Report drafts

## Why

Once a finding is verified by hand, writing the advisory is the slow part, and a vague report is the most common reason a maintainer stalls. Everything a draft needs is already in the DB.

## How

A "Draft report" button on a finding (enabled once the repo is marked Real) fills a template per bug class, no LLM:
- **Title**: "<Class> in <function> of <repo> via <input>" (e.g. "Path traversal in read_note via name").
- **Affected**: package name and the version range from the latest release tag to the scanned commit; a "fixed in" placeholder.
- **CWE** from the class (22, 78, 89, 79, 918, 502, 862) and a CVSS 3.1 vector pre-filled from the class and the route (network, no auth for a public route), for you to adjust.
- **Details**: the vulnerable lines with permalinks at the scanned commit, the input → sink path the checker found, and Semgrep's confirmation if any.
- **Reproduction outline** per class (what request or tool call to send). An outline for you to test locally on your own install, not a working exploit.
- **Suggested fix** per class (containment check, argument array, allow-list, prepared statement, escaping) and **where to send it** (the CVE route from plan 15).

Output as Markdown to copy into the GitHub "Report a vulnerability" form or the CNA's form, and saved into the repo's notes.

## Done when
- A finding on a Real repo produces a draft that needs only the reproduction details and the CVSS check filled in by hand.
