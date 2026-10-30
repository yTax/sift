package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"path"
	"regexp"
	"strings"
)

// libraryLangs reads a repo's manifests to tell which of its languages ship as a library, so
// library mode stays off in apps, whose public helpers aren't entry points:
//   - JS: a package.json that isn't private and names an entry point (main, module, exports);
//   - Python: packaging config (setup.py, setup.cfg, pyproject with [project] or [tool.poetry]);
//   - Go: a module with no main package at the root or under cmd/.
//
// A root Dockerfile, compose file or app entry script (manage.py, app.py, main.py) marks a
// deployed app for JS and Python, packaging config or not.
func libraryLangs(files []*zip.File, strip bool) map[string]bool {
	out := map[string]bool{}
	app, goMod, goMain := false, false, false
	for _, f := range files {
		name := f.Name
		if strip {
			if i := strings.IndexByte(name, '/'); i >= 0 {
				name = name[i+1:]
			}
		}
		depth := strings.Count(name, "/")
		base := path.Base(name)
		switch {
		case base == "package.json" && depth <= 2 && !strings.Contains(name, "node_modules/"):
			if b := readZipEntry(f, 256<<10); jsLibraryManifest(b) {
				out["js-ts"] = true
			}
		case depth == 0 && (base == "setup.py" || base == "setup.cfg"):
			out["python"] = true
		case depth == 0 && base == "pyproject.toml":
			if b := readZipEntry(f, 256<<10); bytes.Contains(b, []byte("[project]")) || bytes.Contains(b, []byte("[tool.poetry]")) {
				out["python"] = true
			}
		case depth == 0 && base == "go.mod":
			goMod = true
		case depth == 0 && base == "main.go", strings.HasPrefix(name, "cmd/"):
			goMain = true
		case depth == 0 && (base == "Dockerfile" || strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose.") ||
			base == "manage.py" || base == "app.py" || base == "main.py"):
			app = true
		}
	}
	if app {
		out["js-ts"], out["python"] = false, false
	}
	out["go"] = goMod && !goMain
	return out
}

func jsLibraryManifest(b []byte) bool {
	var m struct {
		Private bool            `json:"private"`
		Main    string          `json:"main"`
		Module  string          `json:"module"`
		Exports json.RawMessage `json:"exports"`
	}
	if len(b) == 0 || json.Unmarshal(b, &m) != nil || m.Private {
		return false
	}
	return m.Main != "" || m.Module != "" || len(m.Exports) > 0
}

func readZipEntry(f *zip.File, limit int64) []byte {
	if int64(f.UncompressedSize64) > limit {
		return nil
	}
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	b, _ := io.ReadAll(io.LimitReader(rc, limit))
	return b
}

// Library mode. In a library the attacker's input arrives as the arguments of its exported
// functions, which no handler registration marks. Those parameters count as input too, at low
// confidence, so a package like `export function gitDiff(a, b) { execSync("git diff " + a) }`
// is caught without making every app helper loud.

// checkerLibrary switches library mode on; off only to measure what it changes on the bench.
var checkerLibrary = true

type jsExportSet struct {
	names   map[string]bool
	classes [][2]int // spans of exported classes, whose public methods are exported
}

var (
	jsExportList   = regexp.MustCompile(`(?:module\.exports\s*=|export)\s*\{([^}]*)\}`)
	jsExportAssign = regexp.MustCompile(`(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=|module\.exports\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$|export\s+default\s+([A-Za-z_$][\w$]*)\s*;?\s*$`)
	jsClassHead    = regexp.MustCompile(`(?m)^[ \t]*(?:export\s+(?:default\s+)?)?class\s+([A-Za-z_$][\w$]*)[^{\n]*\{`)
	jsExportHead   = regexp.MustCompile(`\bexport\s|\bexports\.[\w$]+\s*=|module\.exports(\.[\w$]+)?\s*=`)
	jsConstName    = regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=`)
	jsPrivateHead  = regexp.MustCompile(`\b(private|protected)\s|#[\w$]+\s*\(`)
)

func jsExports(src, lang string) *jsExportSet {
	e := &jsExportSet{names: map[string]bool{}}
	if lang != "js-ts" {
		return e
	}
	for _, m := range jsExportList.FindAllStringSubmatch(src, -1) {
		for _, part := range strings.Split(m[1], ",") {
			// `a`, `a as b`, and CommonJS `key: a`
			if id := identRe.FindString(strings.TrimSpace(part)); id != "" {
				e.names[id] = true
			}
			if i := strings.IndexByte(part, ':'); i >= 0 {
				if id := identRe.FindString(part[i+1:]); id != "" {
					e.names[id] = true
				}
			}
		}
	}
	for _, line := range strings.Split(src, "\n") {
		for _, m := range jsExportAssign.FindAllStringSubmatch(strings.TrimSpace(line), -1) {
			for _, g := range m[1:] {
				if g != "" {
					e.names[g] = true
				}
			}
		}
	}
	for _, m := range jsClassHead.FindAllStringSubmatchIndex(src, -1) {
		name := src[m[2]:m[3]]
		if strings.Contains(src[m[0]:m[2]], "export") || e.names[name] {
			e.classes = append(e.classes, [2]int{m[1] - 1, matchBrace(src, m[1]-1)})
		}
	}
	return e
}

// exported reports whether the function whose head starts at headOff is part of the API.
func (e *jsExportSet) exported(src, lang, name string, headOff int) bool {
	switch lang {
	case "go":
		return name != "" && name[0] >= 'A' && name[0] <= 'Z'
	case "js-ts":
		ls := strings.LastIndexByte(src[:headOff], '\n') + 1
		le := strings.IndexByte(src[headOff:], '\n')
		if le < 0 {
			le = len(src) - headOff
		}
		before := src[ls:headOff]
		if jsExportHead.MatchString(before) || name != "" && e.names[name] {
			return true
		}
		// `export const name = (...) => {` or a name exported further down
		if m := jsConstName.FindStringSubmatch(before); m != nil && e.names[m[1]] {
			return true
		}
		if name == "" || strings.HasPrefix(name, "_") || name == "constructor" || jsPrivateHead.MatchString(src[ls:headOff+le]) {
			return false
		}
		for _, c := range e.classes {
			if headOff > c[0] && headOff < c[1] {
				return true
			}
		}
	}
	return false
}

var pyClassLine = regexp.MustCompile(`^\s*class\s+(\w+)`)

// pyPublic reports whether a Python function is public API: a module-level function or a
// method of a public class, with a public name. Nested functions are implementation.
func pyPublic(lines []string, head, indent int, name string) bool {
	if strings.HasPrefix(name, "_") {
		return false
	}
	for j := head - 1; j >= 0 && strings.HasPrefix(strings.TrimSpace(lines[j]), "@"); j-- {
		if d := lines[j]; strings.Contains(d, "click.") || strings.Contains(d, ".command") || strings.Contains(d, "pytest") {
			return false // CLI commands get their arguments from whoever runs them
		}
	}
	if indent == 0 {
		return true
	}
	for j := head - 1; j >= 0; j-- {
		t := strings.TrimRight(lines[j], " \t\r")
		tt := strings.TrimSpace(t)
		if tt == "" || strings.HasPrefix(tt, "@") || strings.HasPrefix(tt, "#") {
			continue
		}
		if len(t)-len(strings.TrimLeft(t, " \t")) < indent {
			m := pyClassLine.FindStringSubmatch(t)
			return m != nil && !strings.HasPrefix(m[1], "_")
		}
	}
	return false
}

// libNotData are parameter names that hold objects, callbacks or plumbing, not attacker data.
var libNotData = map[string]bool{"self": true, "cls": true, "this": true, "logger": true, "log": true, "callback": true,
	"cb": true, "fn": true, "func": true, "done": true, "next": true, "resolve": true, "reject": true, "loop": true,
	"ctx": true, "context": true, "client": true, "session": true, "db": true, "conn": true, "cursor": true,
	"req": true, "res": true, "request": true, "response": true, "w": true, "r": true, "t": true, "b": true}

var (
	libJSNotData = regexp.MustCompile(`^\s*(number|boolean|bigint|Function|\(.*\)\s*=>.*|[A-Z]\w*(Callback|Handler|Logger|Client|Options)\b.*)\s*$`)
	libPyNotData = regexp.MustCompile(`^\s*(int|float|bool|Callable\b.*|Optional\[(int|float|bool)\]|.*Logger|.*Session|.*Client)\s*$`)
	libGoData    = regexp.MustCompile(`^(\.\.\.)?(string|\[\]string|\[\]byte|any|interface\{\}|map\[string\](string|any|interface\{\})|\*?url\.URL)$`)
)

// libraryParams picks the parameters of an exported function that can carry attacker data:
// strings, bytes, untyped values and plain containers, not numbers, callbacks or clients.
func libraryParams(params, lang string) []string {
	pieces := splitParams(params)
	var out []string
	switch lang {
	case "go":
		typ := ""
		for i := len(pieces) - 1; i >= 0; i-- { // `a, b string`: the type comes last
			f := strings.Fields(pieces[i])
			if len(f) == 0 {
				continue
			}
			if len(f) > 1 {
				typ = strings.Join(f[1:], "")
			}
			if libGoData.MatchString(typ) && !libNotData[f[0]] {
				out = append(out, f[0])
			}
		}
	case "js-ts", "python":
		for _, p := range pieces {
			p = strings.TrimLeft(strings.TrimSpace(p), "*.")
			if p == "" || p[0] == '{' || p[0] == '[' {
				continue
			}
			name := identRe.FindString(p)
			if name == "" || !strings.HasPrefix(p, name) || libNotData[name] || typeWords[name] {
				continue
			}
			typ := strings.TrimSpace(p[len(name):])
			typ = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(typ, "?"), ":"))
			if i := strings.IndexByte(typ, '='); i >= 0 && !strings.HasPrefix(typ[i:], "=>") {
				typ = strings.TrimSpace(typ[:i])
			}
			if typ != "" && (lang == "js-ts" && libJSNotData.MatchString(typ) || lang == "python" && libPyNotData.MatchString(typ)) {
				continue
			}
			out = append(out, name)
		}
	}
	return out
}

// splitParams splits a parameter list at its top-level commas.
func splitParams(params string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(params); i++ {
		switch params[i] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}':
			depth--
		case '>':
			if i == 0 || params[i-1] != '=' { // not an arrow
				depth--
			}
		case '"', '\'', '`':
			i = skipString(params, i) - 1
		case ',':
			if depth == 0 {
				out = append(out, params[start:i])
				start = i + 1
			}
		}
	}
	return append(out, params[start:])
}
