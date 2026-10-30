# Plan 14 — Library: drop-in files and builders

**Status: core done.** `library.go`, `web/library.js`, `web/settings.js`.

## Why

Adding a scene, a checker or a Semgrep rule meant writing YAML by hand next to the binary, and nothing told you whether it worked until a run. The panel had no settings screen even though the API existed.

## What's there

- **Four drop-in folders** next to sift: `dorks/`, `sinks/`, `checkers/`, `semgrep/`. Each kind is the bundled files (read from the binary) overlaid by yours: a file with a bundled file's name replaces it, any other file adds to it. Bundled files are no longer copied out on first start, so improvements to them reach you on update; old copies identical to a bundled file are removed at startup.
- **Library tab**: every file with its origin (built-in / edited / yours), an on/off switch (scenes per scene; the others through `Settings.DisabledFiles`), and an editor.
- **Builders** for scenes and checkers (form ↔ YAML, converted server-side so the browser needs no YAML parser), a YAML editor for everything.
- **Live tests before saving**: a scene query runs its first page against the real search and shows the count and sample repos; a checker, sink profile or Semgrep rule file runs over a pasted code sample and shows findings plus every line a pattern matched (so "sink found, no input reached it" is visible).
- **Settings tab** over `/api/settings`; the token field is write-only.

## Safety

These endpoints write files, and the panel will face the internet behind oauth2-proxy (plan 8b), so:
- File names are reduced to `[a-z0-9_-]` + `.yaml`; no separators or dots, so nothing leaves the folder. Unknown kinds are refused.
- A file is parsed exactly as a run would load it before it's written (regexes compile, dork ids don't clash, rule files have ids, languages and `metadata.class`). 256 KB cap. Atomic write.
- Delete moves the file to `<kind>/.trash/`; bundled files can't be deleted, only switched off. Symlinks are refused.
- Regexes are RE2 (no catastrophic backtracking). Semgrep tests run the rule over the sample in a fresh temp folder; nothing in the sample executes.
- Same Host check and `X-Sift` header as every other POST.

## Next
- "Run on a repo": try an unsaved checker over a repo already in the DB (re-download its zip, run, discard).
- Per-query on/off switches and the scene's contact/prescore toggles in the scene builder (the API exists: `/api/query`, `/api/category`).
