package main

import (
	"regexp"
	"strings"
)

// Per-function data flow for the checkers, and the same-file helpers around it (plan 12,
// layer 3). A checker only reads one function at a time, so on its own it misses helpers in
// both directions:
//   - a cleaning helper (`_safe_resource_file(base, name)` running relative_to) makes the
//     argument safe, though the handler shows no check;
//   - a sink wrapper (`def run(cmd): subprocess.run(cmd, shell=True)`) makes a call to it as
//     dangerous as the sink, though the handler shows no sink.
// Both are summarised per file before the handlers are read, one level deep.

// checkerHelpers switches layer 3 on; off only to measure what it changes on the bench.
var checkerHelpers = true

type fileCtx struct {
	lang          string
	lines         []string
	inBlock       []bool
	source        *regexp.Regexp
	interp        interpCache
	plainResponse bool // the file's Response is Werkzeug's (text/plain) or Starlette's (no type), not Flask's (text/html)
}

type taintState struct {
	direct, tainted, built map[string]bool
	hasInput               bool
	body                   string
}

// taint follows the inputs through the function's assignments: tainted names are the inputs
// plus whatever is assigned from them, built ones have input pasted into a string.
func (fc *fileCtx) taint(f fnSpan, inputs []string) taintState {
	lines, lang, source := fc.lines, fc.lang, fc.source
	t := taintState{direct: map[string]bool{}, tainted: map[string]bool{}, built: map[string]bool{}}
	for _, n := range inputs {
		t.direct[n] = true
		t.tainted[n] = true
	}
	t.body = strings.Join(lines[f.start:f.end+1], "\n")
	// most functions aren't handlers and read no request data: only no-input checkers apply
	t.hasInput = len(t.direct) > 0 || source != nil && source.MatchString(t.body)
	for pass := 0; t.hasInput && pass < 2; pass++ { // two passes so order doesn't matter much
		for i := f.start; i <= f.end; i++ {
			for _, re := range assignRes[lang] {
				m := re.FindStringSubmatch(lines[i])
				if m == nil {
					continue
				}
				rhs := m[2]
				hasSource := source != nil && source.MatchString(rhs)
				n := containsName(rhs, t.tainted)
				if n == "" && !hasSource {
					continue
				}
				if cl := checkerCleaners[lang]; cl != nil && cl.MatchString(rhs) {
					break
				}
				isBuilt := hasSource && fc.interp.interpolated(lang, rhs, source.FindString(rhs)) ||
					n != "" && (t.built[n] || fc.interp.interpolated(lang, rhs, n))
				for _, name := range lhsNames(m[1]) {
					if name != "_" && name != "err" {
						t.tainted[name] = true
						if isBuilt {
							t.built[name] = true
						}
					}
				}
				break
			}
		}
	}
	return t
}

type sinkHit struct {
	line      int
	via, conf string
	w         *wrapper // set when the sink is a call to a same-file wrapper
	passes    bool     // summary mode: the input reached the call as is, not pasted into a string
}

var (
	pyKeywordArg    = regexp.MustCompile(`^(\w+)\s*=[^=]`)
	pyPathKeyword   = map[string]bool{"path": true, "filename": true, "file": true, "filepath": true, "file_path": true, "fp": true, "src": true, "dst": true, "directory": true}
	pyBareResponse  = regexp.MustCompile(`^Response\(`)
	plainResponseRe = regexp.MustCompile(`(?s)from\s+(werkzeug|starlette|fastapi)[\w.]*\s+import\s+(\([^)]*|[^\n]*)\bResponse\b`)
	htmlContentType = regexp.MustCompile(`text/html`)
)

// scan returns the sink lines of one checker in f that input reaches. In summary mode (reading
// a possible wrapper) the parameters are the input, and an argument passed through untouched
// counts even for checkers that want input pasted into a string: the caller may paste it.
func (fc *fileCtx) scan(f fnSpan, c *Checker, t taintState, hs *helperSet, summary bool) []sinkHit {
	lines, lang := fc.lines, fc.lang
	l := c.Langs[lang]
	var out []sinkHit
	guardAt := -2 // first line with a guard, looked up on the first sink hit (-1: none)
	for i := f.start; i <= f.end; i++ {
		line := lines[i]
		if commentLine(line, lang) || fc.inBlock[i] {
			continue
		}
		var loc []int
		for _, re := range l.sinks {
			if loc = re.FindStringSubmatchIndex(line); loc != nil {
				if g := re.SubexpIndex("arg"); g > 0 && loc[2*g] >= 0 {
					loc = []int{loc[0], loc[1], loc[2*g], loc[2*g+1]}
				} else {
					loc = loc[:2]
				}
				break
			}
		}
		var w *wrapper
		if loc == nil && hs != nil {
			for _, cand := range hs.wrappers {
				if cand.fn == f.name {
					continue
				}
				if m := cand.call.FindStringSubmatchIndex(line); m != nil {
					loc, w = []int{m[2], m[3]}, cand
					break
				}
			}
		}
		if loc == nil || i == f.head || defLine.MatchString(line) {
			continue // a method named exec() is not a call to exec()
		}
		if !inCode(line, loc[0], lang) {
			continue // quoted in a log message or a trailing comment
		}
		if w == nil && lang == "python" && c.Class == "xss" && pyBareResponse.MatchString(line[loc[0]:]) && fc.plainResponse {
			// Werkzeug's Response is text/plain and Starlette's sends no type: not HTML unless said so
			window := line
			if i+1 <= f.end {
				window += lines[i+1]
			}
			if !htmlContentType.MatchString(window) {
				continue
			}
		}
		via, conf, passes := "", "medium", false
		if !l.NoInput || w != nil {
			args := line[loc[0]:]
			if i+1 <= f.end && !callCloses(args) {
				args += " " + lines[i+1] // the call wraps
			}
			if w != nil {
				args = nthArg(args, w.arg)
			} else {
				args = narrowArg(l, line, args, loc)
			}
			if args == "" {
				continue
			}
			if lang == "python" && l.Arg == "first" && w == nil {
				// FileResponse(file_id=..., name=...): a model of the same name, not a path
				if m := pyKeywordArg.FindStringSubmatch(args); m != nil && !pyPathKeyword[m[1]] {
					continue
				}
			}
			if lang == "php" {
				args = phpTestOnly.ReplaceAllString(args, "") // input only compared, never output
			}
			if hs.cleans(args) {
				continue // the argument goes through a same-file helper that checks it
			}
			if !l.Interpolated {
				args = blankLiterals(args, lang) // "Hello {{ name }}" holds no input
			}
			if l.Interpolated && (w == nil || w.needBuilt) {
				via, conf = interpolatedInput(fc.interp, lang, args, fc.source, t.direct, t.tainted, t.built)
				if via == "" && summary {
					if n := containsName(args, t.direct); n != "" {
						via, conf, passes = n, "high", true
					}
				}
			} else if fc.source != nil && fc.source.MatchString(args) {
				via, conf = fc.source.FindString(args), "high"
			} else if n := containsName(args, t.direct); n != "" {
				via, conf = n, "high"
			} else if n := containsName(args, t.tainted); n != "" {
				via = n
			}
			if via == "" || hs.cleanedVia(fc.lines, f, i, via, lang) {
				continue
			}
		}
		if anyMatch(l.lineGuards, line) {
			continue
		}
		if l.NoInput {
			// the line is the bug itself (a prefix check): a fix anywhere in the function counts,
			// even after it: `if real != home and not real.startswith(home + os.sep)` next line
			if guardAt == -2 {
				guardAt = -1
				for j := f.start; j <= f.end && len(l.guards) > 0; j++ {
					if anyMatch(l.guards, lines[j]) {
						guardAt = j
						break
					}
				}
			}
			if guardAt >= 0 {
				continue
			}
		} else if fc.guarded(l, f, i, t) {
			continue
		}
		out = append(out, sinkHit{line: i, via: via, conf: conf, w: w, passes: passes})
	}
	return out
}

// ---------- same-file helpers ----------

type wrapper struct {
	fn        string // the wrapper's name
	arg       int    // which argument of a call reaches the sink
	needBuilt bool   // the wrapper passes it on as is: only a string with input pasted in counts
	req       bool   // the wrapper's body satisfies the checker's requires (holds the SQL, say)
	sinkLine  int
	call      *regexp.Regexp // group 1 is the call from its name
}

type helperSet struct {
	cleaners []*regexp.Regexp
	wrappers []*wrapper
}

func (hs *helperSet) cleans(args string) bool {
	return hs != nil && anyMatch(hs.cleaners, args)
}

func (hs *helperSet) calledIn(body string) bool {
	if hs == nil {
		return false
	}
	for _, w := range hs.wrappers {
		if w.call.MatchString(body) {
			return true
		}
	}
	return false
}

// cleanedVia reports whether the latest assignment to name before line i takes its value from
// a cleaning helper: `path = _safe_store_resource_path(resource_path)`.
func (hs *helperSet) cleanedVia(lines []string, f fnSpan, i int, name, lang string) bool {
	if hs == nil || len(hs.cleaners) == 0 {
		return false
	}
	for j := i - 1; j >= f.start; j-- {
		for _, re := range assignRes[lang] {
			m := re.FindStringSubmatch(lines[j])
			if m == nil {
				continue
			}
			for _, n := range paramNames(m[1]) {
				if n == name {
					return hs.cleans(m[2])
				}
			}
			break
		}
	}
	return false
}

// callRe matches a call to a same-file function: bare, or on self/this. obj.name() is
// somebody else's method.
func callRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^\w$.>:])((?:self\.|this\.|\$this->|self::|static::)?` + regexp.QuoteMeta(name) + `\s*\()`)
}

const (
	maxCleanerLines = 80
	maxWrapperLines = 200
)

// helpers summarises the file's functions for each active checker: which ones check or clean
// what they're given (they contain one of the checker's guards), and which pass a parameter
// to one of its sinks unguarded.
func (fc *fileCtx) helpers(fns []fnSpan, active []*Checker) map[string]*helperSet {
	out := map[string]*helperSet{}
	plain := *fc
	plain.source = nil // a wrapper's own reads of request data are found when it's read as a handler
	for _, c := range active {
		l := c.Langs[fc.lang]
		hs := &helperSet{}
		for _, g := range fns {
			if g.name == "" || g.end < g.start || g.end >= len(fc.lines) {
				continue
			}
			body := strings.Join(fc.lines[g.start:g.end+1], "\n")
			if g.end-g.start <= maxCleanerLines && (anyMatch(l.guards, body) || anyMatch(l.lineGuards, body)) {
				hs.cleaners = append(hs.cleaners, callRe(g.name))
				continue
			}
			if l.NoInput || len(g.inputs) > 0 || len(g.params) == 0 || len(g.params) > 8 ||
				g.end-g.start > maxWrapperLines || !l.any.MatchString(body) {
				continue
			}
			for idx, p := range g.params {
				if p == "" || p == "self" || p == "cls" || p == "$this" {
					continue
				}
				hits := plain.scan(g, c, plain.taint(g, []string{p}), nil, true)
				if len(hits) == 0 {
					continue
				}
				arg := idx
				if g.params[0] == "self" || g.params[0] == "cls" {
					arg-- // called as self.name(...)
				}
				w := &wrapper{fn: g.name, arg: arg, needBuilt: true, sinkLine: hits[0].line, call: callRe(g.name),
					req: len(l.requires) == 0 || anyMatch(l.requires, body)}
				for _, h := range hits {
					w.needBuilt = w.needBuilt && h.passes
				}
				hs.wrappers = append(hs.wrappers, w)
				break
			}
		}
		out[c.ID] = hs
	}
	return out
}

// nthArg returns argument n (from 0) of the first call in s, or "" when it has fewer.
func nthArg(s string, n int) string {
	open := strings.IndexByte(s, '(')
	if open < 0 || n < 0 {
		return ""
	}
	depth, k, from := 0, 0, open+1
	for i := open + 1; i < len(s); i++ {
		switch s[i] {
		case '"', '\'', '`':
			i = skipString(s, i) - 1
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				if k == n {
					return strings.TrimSpace(s[from:i])
				}
				return ""
			}
			depth--
		case ',':
			if depth == 0 {
				if k == n {
					return strings.TrimSpace(s[from:i])
				}
				k++
				from = i + 1
			}
		}
	}
	if k == n {
		return strings.TrimSpace(s[from:])
	}
	return ""
}

var phpVarRe = regexp.MustCompile(`\$\w+`)

// orderedParams lists a function's parameter names in order; "" stands for one it can't name
// (a destructured object), so positions stay right.
func orderedParams(params, lang string) []string {
	var out []string
	piece := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		name := ""
		switch lang {
		case "php":
			name = phpVarRe.FindString(p)
		case "go":
			name = strings.Fields(p)[0]
		default:
			p = strings.TrimLeft(p, "*.&")
			if id := identRe.FindString(p); id != "" && strings.HasPrefix(p, id) {
				name = id
			}
		}
		out = append(out, name)
	}
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
		case '"', '\'':
			i = skipString(params, i) - 1
		case ',':
			if depth == 0 {
				piece(params[start:i])
				start = i + 1
			}
		}
	}
	piece(params[start:])
	return out
}

// guarded reports whether a guard protects the sink on line i: a guard line before it that
// touches the input or something built from it. A validator run on some other value in the
// same function (`validate_safe_path(config_dir)`) doesn't protect this sink.
func (fc *fileCtx) guarded(l *checkerLang, f fnSpan, i int, t taintState) bool {
	if len(l.guards) == 0 {
		return false
	}
	for j := f.start; j <= i; j++ {
		line := fc.lines[j]
		if !anyMatch(l.guards, line) {
			continue
		}
		if l.GuardsAnywhere || containsName(line, t.tainted) != "" || fc.source != nil && fc.source.MatchString(line) {
			return true
		}
	}
	return false
}

// blankLiterals empties the string literals that can't interpolate (plain quotes; not
// f-strings, JS templates or PHP double quotes), so a name written inside one isn't read as
// the variable.
func blankLiterals(s, lang string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '"' && c != '\'' && c != '`' {
			b.WriteByte(c)
			continue
		}
		end := skipString(s, i)
		prev := byte(0)
		if i > 0 {
			prev = s[i-1]
		}
		plain := true
		switch lang {
		case "python":
			plain = prev != 'f' && prev != 'F'
		case "js-ts":
			plain = c != '`'
		case "php":
			plain = c == '\''
		}
		if plain {
			b.WriteByte(c)
			b.WriteByte(c)
		} else {
			b.WriteString(s[i:end])
		}
		i = end - 1
	}
	return b.String()
}

// lhsNames are the names an assignment sets. Unlike parameter lists (paramNames), type words
// don't apply: `next := r.URL.Query().Get("next")` is a value here, not Express's callback.
func lhsNames(lhs string) []string {
	var out []string
	for _, id := range identRe.FindAllString(lhs, -1) {
		if !jsKeywords[id] && id != "const" && id != "let" && id != "var" {
			out = append(out, id)
		}
	}
	return out
}
