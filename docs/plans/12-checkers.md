# Plan 12 — Bug checkers: from "this repo has sinks" to "this line looks like bug X"

**Status:** layers 1 and 2 built (`checkers.go`, `defaults/checkers`, `defaults/semgrep`, `taint.go`). Added beyond the list below: `sql-from-input`, `xss-from-input` and `wp-missing-authz` (WordPress AJAX/REST handlers without capability or nonce checks), PHP support, and noise fixes from real runs (handler-only inputs, path/host-only arguments, server-set request fields, typed route params, skipping build scripts).

## Why

Today's scan is grep. It sees `exec(` and stops, so a repo's hit list is hundreds of lines you still have to read yourself. A checker asks one precise question about one bug class ("does a tool argument reach `readFile` with no containment check?") and answers with a file, a line and a reason. Fewer hits, each one worth opening. This is the step where sift starts pointing at bugs instead of at repos.

Start with the MCP / AI-agent scene: it's young code, the bug classes are well known (path traversal, command injection, SSRF in tool handlers), and the same mistakes get copied between projects.

## Two layers

Checkers come in two strengths. Build layer 1 first; it runs on every scanned repo. Layer 2 runs on the top of the list.

### Layer 1 — function-scoped checks in Go, during the normal scan

Pure Go, no parser library, so the single binary and `CGO_ENABLED=0` cross-compile stay intact (tree-sitter's Go bindings need cgo; see "Not chosen" below).

For each file the scanner already reads:
1. **Cut it into functions.** Brace matching for JS/TS/Go/Java/PHP/C-like (skip strings and comments while counting), indentation for Python. Approximate is fine: the goal is "same handler", not a perfect AST.
2. **Find the inputs of the function.** Its parameters, plus known input shapes per framework: `req.query/params/body`, `request.args/json/form`, MCP tool handler arguments (`args`, `arguments`, `params`), Go `r.URL.Query()`, `r.FormValue`.
3. **Track names textually** through simple assignments (`const p = args.path`, `p = os.path.join(base, name)`), a few hops deep.
4. **Report when a tracked name reaches a sink argument** and no guard for that class appears between them.

Each checker is a small struct: class, languages, input shapes, sink regexes, guard regexes, the message, and a weight. Keep them data-driven in YAML next to the sink profiles (`checkers/*.yaml`), so adding one doesn't need a rebuild.

First checkers (all seen in real MCP CVEs):

| ID | Class | Fires when | Guard that silences it |
|---|---|---|---|
| `prefix-containment` | path traversal | the only "inside the allowed dir" check is `startsWith(base)` / `HasPrefix` / `.startswith` on an unresolved or un-normalised path, so `/data-evil` passes a check for `/data` | `path.relative`/`filepath.Rel` with a `..` check, or comparing against `base + sep` after `realpath`/`EvalSymlinks` |
| `tool-path-to-fs` | path traversal | a tool/route input reaches `readFile`/`open`/`os.Open`/`send_file` | `resolve`+containment check, an allow-list lookup |
| `shell-from-input` | command injection | input reaches `exec`/`execSync`/`subprocess.*(…, shell=True)`/`os.system`/`sh -c` inside a template string or concatenation | argument-array form with no shell, `shlex.quote`, an allow-list |
| `fetch-from-input` | SSRF | input reaches `fetch`/`axios`/`requests.get`/`http.Get` as the URL | host allow-list, blocking private ranges, a fixed base URL the input can't escape |
| `route-without-auth` | missing auth | an admin-looking route (`/admin`, `/api/settings`, `/users`, `/exec`) registered with no auth middleware in its chain while other routes have one | the app's auth middleware name appears on the route or its router |
| `unsafe-deserialize` | RCE | input reaches `pickle.loads`, `yaml.load` without SafeLoader, `unserialize`, Java `ObjectInputStream` | safe loader variants |
| `zip-slip` | path traversal | archive entry names joined to a destination with no containment check | `filepath.Rel` / `startsWith(dest + sep)` after cleaning |

Store results as `ScanResult.Findings []Finding{Checker, Class, Path, Line, EndLine, Message, Snippet, Confidence}`. Add a `findings` score part (weighted high, default 4) so one solid finding outranks a pile of raw sinks. On the repo page findings go first, above hot files.

**Measure precision before trusting it.** Keep a `testdata/checkers/` folder of small real-world snippets: vulnerable ones from published GHSAs (the pre-fix code), and the fixed versions. Every checker needs at least two "fires on the bug" and two "silent on the fix" cases. Then run it over the scanned MCP set and read 20 findings by hand. If more than about half are noise, tighten the guard list before shipping it.

### Layer 2 — Semgrep taint rules on the top N

Semgrep CE's taint mode understands real syntax and data flow inside a function, which is exactly what layer 1 approximates. Write each checker class as a custom Semgrep taint rule too (`semgrep/rules/mcp-*.yaml`: sources = tool/route inputs, sinks = the dangerous calls, sanitizers = the guards above). Plan 7 already wires up running Semgrep on the top N; this plan supplies sift's own rules for it, run alongside the registry packs.

When both layers flag the same line, mark the finding `confirmed by semgrep` and bump its confidence.

### Layer 3 — same-file wrappers and response types

**Status: built** (`checkers_flow.go`, `checkers_lib.go`), measured on the bench (plan 17). Cleaning helpers silence a sink when the argument passes through them; sink wrappers become sinks at their call sites (one level, same file); a bare Python `Response` only counts as HTML when it isn't Werkzeug's or Starlette's or says `text/html`. Added from the bench: library mode (exported functions' parameters are input, low confidence) and input-aware guards. Same-package wrappers across files are not built yet.

Found by reading real results: the checker only sees one function, so it misses helpers in both directions.
- **Escaping helpers** (false positives): `HTMLResponse(_error_page(f"...{error}"))` was flagged although `_error_page` runs `html.escape` on its argument. Build a per-file summary of each function: does it pass parameter N through a known cleaner (escape, basename, quote, int, prepare)? A call to such a helper counts as cleaning its argument.
- **Sink wrappers** (missed bugs): `def run(cmd): subprocess.run(cmd, shell=True)` called from a handler with input. The same summary records "parameter N reaches sink X", and a call to the wrapper with input becomes a finding at the call site (one level deep, same file first, then same package by import).
- **Response types**: Werkzeug's `Response` defaults to `text/plain`, Starlette's `Response` with no `media_type` sends no content type; neither is reflected XSS on its own. Know the defaults per framework and only flag HTML ones (`flask.Response`, `HTMLResponse`, `make_response` of a string, `mimetype="text/html"`).

Each addition comes with fixtures from the run that exposed it.

## Not chosen

- **tree-sitter in-process:** the best parser, but the Go bindings need cgo, which breaks the pure-Go cross-compile to Windows and the Oracle ARM box (plan 9). Semgrep gives us tree-sitter-quality parsing as an external binary instead.
- **Running the target app and sending payloads:** ruled out. sift never runs downloaded code.

## Files
- `checkers.go` — function splitter, input/name tracking, checker engine.
- `defaults/checkers/*.yaml` — checker definitions (embedded like dorks and sinks).
- `testdata/checkers/` — vulnerable/fixed snippet pairs.
- `semgrep/rules/` — the layer-2 taint rules.
- `scan.go` — call the checkers per file; `score.go` — `findings` part; `web/app.js` — findings card.

## Done when
- Each checker fires on its vulnerable fixtures and stays silent on the fixed ones (table test).
- On the saved MCP run, the top 20 findings have been read by hand and at least half are worth a closer look.
- A repo with one high-confidence finding ranks above a repo with ten times the raw sinks and no findings.
