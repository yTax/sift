# Plan 17 — Bench: fixed advisories as an answer key

**Status: built.** `bench.go`, the Bench card on the Library tab, `sift -bench` / `-bench-collect N`.

## Why

Checker changes were judged by eyeballing a few repos. Every advisory with a fix commit is a free, labelled test: the code before the fix has a real bug, the code after it doesn't. Scoring the checkers on hundreds of those tells what a change really does, and the misses say what to build next.

## How

- **Cases**: reviewed GitHub advisories (npm, pip, go, composer) whose CWEs map to a class, with their fix commit (or merged PR). Each case keeps the fix's modified source files before and after, gzipped, in `data/bench/cases/` (third-party code: never in the repo, never run). Collected by `-bench-collect N`, the panel button, and the variant feed every day.
- **Score**: a case is *caught* when a checker of its class fires on the before-file at the change (within 3 lines, or in the innermost function around it), *cleared* when the after-file is quiet there, *still* when it isn't (the checker doesn't see the fix), *other* when only another class fired. Misses get a reason:
  - `no-sink`: no checker sink near the change (the fix tightened a validator, or the call is unknown),
  - `no-input`: a sink, but no input sift recognises reaches it,
  - `flow`: both there, an engine gap.
- **History**: one line per checker set (`data/bench/history.json`), so the card shows what a change did.

## First results (1,842 cases, 180 days)

| | caught | cleared |
|---|---|---|
| checkers as they were | 18 (1%) | 12 |
| + same-file helpers (plan 12 layer 3) | 28 (2%) | 16 |
| + library mode, input-aware guards, new checkers | 159 (9%) | 70 |

What the numbers taught:
- **Library mode was the gap.** Most advisories are in packages, where the input is the caller's argument. Exported functions' data parameters now count as input, at low confidence (weight ×0.25, shown as "library API"), so apps don't get louder.
- **A guard anywhere in the function silenced every sink in it.** A guard now counts only on a line that touches the input (`guards_anywhere: true` keeps the old rule for configuration guards like a sandboxed template environment).
- **Name-based validator guards cost more than they gave** (−27 caught): `validateUrl()` is often the weak code the advisory is about, and `basename()` names an upload while the full path is still opened. Only structural guards were kept (`re.fullmatch`, anchored `.test()`, `MatchString`, `securejoin`, tar `filter='data'`).
- **Picked by frequency**: missing-auth (644), prototype pollution (73), open redirect (46), template injection (29) had no checker. Added `route-auth-gap` (a route without the auth most of its siblings have), `proto-pollution`, `redirect-from-input`, `template-from-input`.
- **Still hard**: `no-sink` is ~750 misses, mostly validator bypasses (encoded `../`, IPv6 loopback, DNS rebinding) and authorization logic. Text patterns won't reach those; that's CodeQL territory (7b).

## Next
- A `weak-guard` checker for SSRF blocklists done by string comparison (`hostname === "localhost"`, `startsWith("127.")`) without resolving the address.
- Read the `flow` misses one by one; each is an engine bug.
- Precision: the bench measures recall. Every real run's review stays the precision check.
