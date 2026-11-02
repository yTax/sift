# Plan 18 — Evidence: trust what sift says, and rank by it

**Status: built.** `precision.go`, `defaults/precision.json`, `checkers_flow.go` (`trace`), `checkers_auth.go` (`proxyAuthGaps`), `taint.go` (`findingsWeight`), `score.go`.

## Why

Reviewing the top leads by hand, two were worth anything. Three causes: the bench only measured missed bugs, so nothing scored false alarms; one helper showed up as twenty findings and lifted the repo's score each time; and judging a finding meant opening the file, since sift said what fired but not why.

## A. Precision bench

The real bench asks "did sift catch the bug". This one asks "does sift still fire on what a human already read and called safe".

- `defaults/precision.json`: leads read by hand. Repo, path, checker, the text of the line, `real` or `false`, and why. Short, public, and in the repo.
- The files themselves are snapshots in `data/bench/precision/` (third-party code, gitignored, never run), fetched once. A line is found by its text, so a snapshot refresh doesn't break a label; a line that's gone shows as `stale`.
- `sift -bench` and the Bench card show false alarms silenced and real bugs kept. Silencing a false alarm by losing a real label is visible at once.
- Every review adds labels. Some false alarms can't be silenced yet (they need cross-file reading); they stay in the list as the to-do.

## B. Unprotected proxy checker

`unprotected-proxy` (Go-coded, class `missing-auth`): a catch-all route that forwards any path upstream, adds the server's own credential from the environment, and has no login check in the handler. Anyone who can reach it acts with that credential.

Shape from a real lead: a Next.js `[...path]` route whose siblings check an admin session or send the user's own cookie, while it sends a service token. Covers Next catch-all routes, Express `req.originalUrl` / `req.params[0]` and FastAPI `{x:path}`. A `middleware.ts` elsewhere can cover it, which one file can't see, so it stays medium confidence and says so.

## C. "Why this fired"

Findings now carry a `trace`: where the input enters, each assignment it goes through, a same-file helper's sink line, and the sink. The repo page shows it under each finding along with the guards the checker looked for, so a lead can be judged without opening the file.

## D. Root causes

Each finding gets a `group`: findings through the same helper, the same input in the same function, or the route gaps of one file are one cause. The repo page shows one per cause with the rest folded under it, and the list chip counts causes.

## E. Rank on evidence

- A cause counts once, at its strongest finding; later causes count less (×0.7 each), so the third is worth about half the first.
- The total is multiplied by 0.6 + 0.4 × (findings part ÷ 10). A repo with many sinks and no finding tops out at 60; volume alone can't reach the top.

## Later

- Mark a single finding real or dud in the panel, which adds a label and feeds plan 13.
- Read the repo's file list for a Next `middleware.ts`, to silence `unprotected-proxy` when one covers the route.
