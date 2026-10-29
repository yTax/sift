package main

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Checkers look for one bug class at a time inside a single function: an input of a request or
// tool handler reaching a dangerous call with no guard in between. It's text-level data flow,
// not a real parser, so it aims to point at lines worth reading, not to prove a bug (plan 12).

type Checker struct {
	ID      string                  `yaml:"id"`
	Class   string                  `yaml:"class"`
	Weight  float64                 `yaml:"weight"`
	Message string                  `yaml:"message"`
	Langs   map[string]*checkerLang `yaml:"langs"`
	File    string                  `yaml:"-"`
}

type checkerLang struct {
	Sinks    []string `yaml:"sinks"`
	Guards   []string `yaml:"guards"`   // any of these in the function before the sink silences it
	Requires []string `yaml:"requires"` // the function must also contain one of these
	// NoInput fires on the sink line alone, without input reaching it. For checks where the
	// line itself is the bug (a weak containment check), not what flows into it.
	NoInput bool `yaml:"no_input"`
	// Interpolated only counts input pasted into a string (template, concatenation, f-string,
	// PHP "...$x"), or a variable built that way. Input passed as a separate argument, like a
	// bound SQL parameter, doesn't count.
	Interpolated bool `yaml:"interpolated"`
	// LineGuards silence a finding only when they're on the sink line itself (esc_html(...), prepare(...)).
	LineGuards []string `yaml:"line_guards"`

	sinks, guards, requires, lineGuards []*regexp.Regexp
}

type Finding struct {
	Checker    string `json:"checker"`
	Class      string `json:"class"`
	Path       string `json:"path"`
	Line       int    `json:"line"`
	Func       string `json:"func,omitempty"`
	Via        string `json:"via,omitempty"` // the input name that reached the sink
	Message    string `json:"message"`
	Snippet    string `json:"snippet"`
	Confidence string `json:"confidence"` // high: an input reaches the sink directly; medium: through assignments
	Weight     float64 `json:"weight"`
}

const (
	maxFindingsPerRepo = 100
	maxFindingsPerFile = 8
)

// loadCheckers reads the bundled checkers, then any *.yaml in extraDir (same id replaces a bundled one).
func loadCheckers(extraDir string) ([]*Checker, []LoadError) {
	byID := map[string]*Checker{}
	var errs []LoadError
	add := func(name string, b []byte) {
		var c Checker
		if err := yaml.Unmarshal(b, &c); err != nil {
			errs = append(errs, LoadError{name, err.Error()})
			return
		}
		c.File = name
		if c.ID == "" {
			c.ID = slugID(strings.TrimSuffix(name, filepath.Ext(name)))
		}
		if c.Weight <= 0 {
			c.Weight = 1
		}
		for lang, l := range c.Langs {
			var err error
			if l.sinks, err = compileAll(l.Sinks); err == nil {
				if l.guards, err = compileAll(l.Guards); err == nil {
					if l.requires, err = compileAll(l.Requires); err == nil {
						l.lineGuards, err = compileAll(l.LineGuards)
					}
				}
			}
			if err != nil {
				errs = append(errs, LoadError{name, lang + ": " + err.Error()})
				return
			}
		}
		byID[c.ID] = &c
	}
	_ = fs.WalkDir(defaultsFS, "defaults/checkers", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isYAML(p) {
			return nil
		}
		b, err := defaultsFS.ReadFile(p)
		if err == nil {
			add(path.Base(p), b)
		}
		return nil
	})
	if entries, err := os.ReadDir(extraDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !isYAML(e.Name()) {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(extraDir, e.Name())); err == nil {
				add(e.Name(), b)
			}
		}
	}
	out := make([]*Checker, 0, len(byID))
	for _, c := range byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, errs
}

func isYAML(name string) bool {
	base := path.Base(filepath.ToSlash(name))
	ext := strings.ToLower(path.Ext(base))
	return (ext == ".yaml" || ext == ".yml") && !strings.HasPrefix(base, "_") && !strings.HasPrefix(base, ".")
}

func compileAll(pats []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range pats {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// checkerLangFor maps a file to the language key checkers use.
func checkerLangFor(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts":
		return "js-ts"
	case ".py":
		return "python"
	case ".php":
		return "php"
	case ".go":
		return "go"
	}
	return ""
}

// ---------- functions ----------

type fnSpan struct {
	name       string
	head       int // line index of the signature
	start, end int // body lines, inclusive
	inputs     []string
}

var (
	// JS/TS function heads. The parameter list is group 1 (or the bare arrow param).
	jsHeads = []*regexp.Regexp{
		regexp.MustCompile(`function\s*\*?\s*([\w$]*)\s*\(([^)]*)\)`),
		regexp.MustCompile(`(?:async\s*)?\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*(?::\s*[^=;{]+)?=>\s*\{`),
		regexp.MustCompile(`(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>\s*\{`),
		regexp.MustCompile(`(?m)^[ \t]*(?:(?:public|private|protected|static|async|override)\s+)*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?::\s*[^{;]+)?\{`),
	}
	// a handler registered on a route/tool: whatever it receives is input
	jsRegister = regexp.MustCompile(`\.(tool|registerTool|addTool|get|post|put|patch|delete|all|handle|setRequestHandler|route)\s*\(`)
	jsInputNames = map[string]bool{"req": true, "request": true, "args": true, "arguments": true, "params": true, "input": true, "ctx": true, "body": true, "query": true}
	jsKeywords   = map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true, "function": true, "return": true, "with": true}

	pyHead     = regexp.MustCompile(`(?m)^([ \t]*)(?:async[ \t]+)?def[ \t]+(\w+)[ \t]*\(`)
	pyRegister = regexp.MustCompile(`^\s*@\s*[\w.]*\.?(tool|get|post|put|patch|delete|route|api_route|websocket|call_tool|resource|prompt|command)\b`)
	pyInputs   = map[string]bool{"request": true, "req": true, "args": true, "arguments": true, "params": true, "payload": true, "body": true}

	goHead      = regexp.MustCompile(`func\s*(?:\([^)]*\)\s*)?(\w*)\s*\(([^)]*)\)`)
	phpHead     = regexp.MustCompile(`\bfunction\s*&?\s*(\w*)\s*\(([^)]*)\)`)
	goInputType = regexp.MustCompile(`\*http\.Request|gin\.Context|echo\.Context|fiber\.Ctx|CallToolRequest|mcp\.\w*Request`)

	identRe = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

	typeWords = map[string]bool{"string": true, "number": true, "boolean": true, "any": true, "unknown": true, "object": true,
		"void": true, "null": true, "undefined": true, "true": true, "false": true, "async": true, "await": true, "const": true,
		"self": true, "cls": true, "str": true, "int": true, "float": true, "bool": true, "dict": true, "list": true, "None": true,
		"Optional": true, "res": true, "response": true, "next": true, "reply": true, "w": true, "z": true}
)

// sources are input expressions that need no parameter, e.g. Flask's global request.
var checkerSources = map[string]*regexp.Regexp{
	"js-ts":  regexp.MustCompile(`\breq\.(query|params|body|headers|cookies|files)\b|\bctx\.(query|params|request\.body)\b|\bprocess\.argv\b`),
	"python": regexp.MustCompile(`\brequest\.(args|form|json|values|files|data|get_json|query_params|path_params|cookies|headers|GET|POST)\b|\bsys\.argv\b`),
	"go":     regexp.MustCompile(`\.URL\.Query\(\)|\.FormValue\(|\.PostFormValue\(|\.PathValue\(|\bc\.(Query|Param|PostForm|FormValue)\(|GetArguments\(\)|\.Params\.Arguments`),
	"php":    regexp.MustCompile(`\$_(GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\[\s*['"](HTTP_\w+|REQUEST_URI|QUERY_STRING|PHP_SELF|PATH_INFO)['"]|php://input|->get_(param|params|json_params|body_params|query_params|file_params)\(`),
}

// cleaners: an assignment whose value starts with one of these (numeric casts and the like)
// produces a value that can't carry an injection, so it isn't tainted.
var checkerCleaners = map[string]*regexp.Regexp{
	"js-ts":  regexp.MustCompile(`^\s*(await\s+)?(parseInt|parseFloat|Number|Boolean|Math\.\w+)\(`),
	"python": regexp.MustCompile(`^\s*(int|float|bool|len)\(`),
	"go":     regexp.MustCompile(`^\s*strconv\.(Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)\(`),
	"php":    regexp.MustCompile(`^\s*(\(int\)|\(float\)|\(bool\)|intval\(|absint\(|floatval\(|boolval\(|sanitize_key\(|count\(|is_numeric\()`),
}

// interpRes are templates for "name is pasted into a string here"; NAME is replaced per name.
var interpRes = map[string][]string{
	"js-ts":  {`\$\{(?:[^}]*?[^\w$])?NAME` + nameE, `\+\s*NAME` + nameE, nameB + `NAME\s*\+`},
	"python": {`\{(?:[^}]*?[^\w$])?NAME` + nameE, `['"]\s*%\s*\(?(?:[^)]*?[^\w$])?NAME` + nameE, `\.format\([^)]*` + nameB + `NAME` + nameE, `\+\s*NAME` + nameE, nameB + `NAME\s*\+`},
	"go":     {`Sprintf\([^)]*` + nameB + `NAME` + nameE, `\+\s*NAME` + nameE, nameB + `NAME\s*\+`},
	"php":    {`"[^"]*NAME` + nameE, `\{NAME`, `\.\s*NAME` + nameE, nameB + `NAME\s*\.[^=]`, `sprintf\([^)]*` + nameB + `NAME` + nameE},
}

const (
	nameB = `(?:^|[^\w$])`
	nameE = `(?:$|[^\w$])`
)

type interpCache map[string]*regexp.Regexp

// interpolated reports whether name is pasted into a string in s.
func (c interpCache) interpolated(lang, s, name string) bool {
	if lang == "python" && !strings.Contains(s, name) {
		return false
	}
	for i, tpl := range interpRes[lang] {
		if lang == "python" && i == 0 && !strings.Contains(s, `f"`) && !strings.Contains(s, `f'`) {
			continue // braces only interpolate inside an f-string
		}
		k := lang + "\x00" + tpl + "\x00" + name
		re, ok := c[k]
		if !ok {
			re = regexp.MustCompile(strings.ReplaceAll(tpl, "NAME", regexp.QuoteMeta(name)))
			c[k] = re
		}
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func lineOf(starts []int, off int) int {
	return sort.Search(len(starts), func(i int) bool { return starts[i] > off }) - 1
}

func lineStarts(s string) []int {
	st := []int{0}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			st = append(st, i+1)
		}
	}
	return st
}

// matchBrace returns the offset of the brace closing the one at open, skipping strings and comments.
func matchBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch c := s[i]; c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		case '"', '\'', '`':
			for i++; i < len(s) && s[i] != c; i++ {
				if s[i] == '\\' {
					i++
				} else if c != '`' && s[i] == '\n' {
					break // unterminated quote: don't swallow the file
				}
			}
		case '/':
			if i+1 < len(s) && s[i+1] == '/' {
				for i < len(s) && s[i] != '\n' {
					i++
				}
			} else if i+1 < len(s) && s[i+1] == '*' {
				if end := strings.Index(s[i+2:], "*/"); end >= 0 {
					i += end + 3
				} else {
					return len(s) - 1
				}
			}
		}
	}
	return len(s) - 1
}

func paramNames(params string) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range identRe.FindAllString(params, -1) {
		if typeWords[id] || jsKeywords[id] || seen[id] || (id[0] >= 'A' && id[0] <= 'Z') {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func braceFunctions(src string, starts []int, lang string) []fnSpan {
	var out []fnSpan
	seen := map[int]bool{}
	addSpan := func(name string, headOff, paramsStart, paramsEnd int) {
		open := strings.IndexByte(src[paramsEnd:min(len(src), paramsEnd+300)], '{')
		if open < 0 {
			return
		}
		open += paramsEnd
		if seen[open] {
			return
		}
		seen[open] = true
		end := matchBrace(src, open)
		params := src[paramsStart:paramsEnd]
		f := fnSpan{name: name, head: lineOf(starts, headOff), start: lineOf(starts, open), end: lineOf(starts, end)}
		switch lang {
		case "js-ts":
			names := paramNames(params)
			from := max(0, headOff-600)
			registered := false
			if locs := jsRegister.FindAllStringIndex(src[from:headOff], -1); len(locs) > 0 {
				between := src[from+locs[len(locs)-1][1] : headOff]
				registered = !strings.Contains(between, ";") && !strings.Contains(between, "\n\n")
			}
			for _, n := range names {
				if registered || jsInputNames[n] {
					f.inputs = append(f.inputs, n)
				}
			}
		case "go":
			for _, p := range strings.Split(params, ",") {
				if goInputType.MatchString(p) {
					if parts := strings.Fields(strings.TrimSpace(p)); len(parts) >= 2 {
						f.inputs = append(f.inputs, parts[0])
					}
				}
			}
		case "php":
			// WordPress REST callbacks get a WP_REST_Request; most other handlers read superglobals (sources)
			for _, n := range paramNames(params) {
				if n == "$request" || n == "$req" {
					f.inputs = append(f.inputs, n)
				}
			}
		}
		out = append(out, f)
	}
	heads := jsHeads
	switch lang {
	case "go":
		heads = []*regexp.Regexp{goHead}
	case "php":
		heads = []*regexp.Regexp{phpHead}
	}
	for hi, re := range heads {
		for _, m := range re.FindAllStringSubmatchIndex(src, -1) {
			switch {
			case lang == "go" || lang == "php":
				addSpan(src[m[2]:m[3]], m[0], m[4], m[5])
			case hi == 0: // function name(params)
				addSpan(src[m[2]:m[3]], m[0], m[4], m[5])
			case hi == 1: // (params) => {
				addSpan("", m[0], m[2], m[3])
			case hi == 2: // param => {
				addSpan("", m[0], m[2], m[3])
			case hi == 3: // method(params) {
				if name := src[m[2]:m[3]]; !jsKeywords[name] {
					addSpan(name, m[0], m[4], m[5])
				}
			}
		}
	}
	return out
}

func pythonFunctions(src string, lines []string, starts []int) []fnSpan {
	var out []fnSpan
	for _, m := range pyHead.FindAllStringSubmatchIndex(src, -1) {
		indent := len(src[m[2]:m[3]])
		name := src[m[4]:m[5]]
		// parameters run to the matching ')'
		depth, i := 1, m[1]
		for ; i < len(src) && depth > 0; i++ {
			switch src[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
		}
		params := src[m[1]:max(m[1], i-1)]
		head := lineOf(starts, m[0])
		sigEnd := lineOf(starts, i)
		end := sigEnd
		for j := sigEnd + 1; j < len(lines); j++ {
			t := strings.TrimRight(lines[j], " \t\r")
			if t == "" {
				continue
			}
			if len(t)-len(strings.TrimLeft(t, " \t")) <= indent {
				break
			}
			end = j
		}
		f := fnSpan{name: name, head: head, start: sigEnd, end: end}
		registered := false
		for j := head - 1; j >= 0 && strings.HasPrefix(strings.TrimSpace(lines[j]), "@"); j-- {
			if pyRegister.MatchString(lines[j]) {
				registered = true
			}
		}
		for _, n := range paramNames(params) {
			if n == "ctx" || n == "context" {
				continue
			}
			if registered || pyInputs[n] {
				f.inputs = append(f.inputs, n)
			}
		}
		out = append(out, f)
	}
	return out
}

// ---------- taint ----------

var (
	assignRes = map[string][]*regexp.Regexp{
		"js-ts": {
			regexp.MustCompile(`(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)`),
			regexp.MustCompile(`(?:const|let|var)\s*\[([^\]]*)\]\s*=\s*(.+)`),
			regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.+)`),
			regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\s*\+?=\s*([^=].*)`),
			regexp.MustCompile(`for\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+(.+)\)`),
		},
		"python": {
			regexp.MustCompile(`^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::[^=]+)?\+?=\s*([^=].*)`),
			regexp.MustCompile(`^\s*for\s+([\w, ]+?)\s+in\s+(.+):`),
		},
		"go": {
			regexp.MustCompile(`^\s*([\w, ]+?)\s*:?=\s*(.+)`),
			regexp.MustCompile(`for\s+([\w, ]+?)\s*:=\s*range\s+(.+)\{`),
		},
		"php": {
			regexp.MustCompile(`^\s*(\$\w+)(?:\[[^\]]*\])*\s*\.?=\s*([^=>].*)`),
		},
	}
)

func containsName(s string, names map[string]bool) string {
	for _, id := range identRe.FindAllString(s, -1) {
		if names[id] {
			return id
		}
	}
	return ""
}

// runCheckers returns the findings for one file.
func runCheckers(name string, b []byte, checkers []*Checker) []Finding {
	lang := checkerLangFor(name)
	if lang == "" || len(checkers) == 0 {
		return nil
	}
	var active []*Checker
	for _, c := range checkers {
		if c.Langs[lang] != nil {
			active = append(active, c)
		}
	}
	if len(active) == 0 {
		return nil
	}
	src := string(b)
	lines := strings.Split(src, "\n")
	starts := lineStarts(src)
	var fns []fnSpan
	if lang == "python" {
		fns = pythonFunctions(src, lines, starts)
	} else {
		fns = braceFunctions(src, starts, lang)
	}
	source := checkerSources[lang]
	interp := interpCache{}
	comment := "//"
	if lang == "python" {
		comment = "#"
	}

	type key struct {
		id   string
		line int
	}
	found := map[key]bool{}
	var out []Finding
	for _, f := range fns {
		if f.end < f.start || f.end >= len(lines) {
			continue
		}
		direct := map[string]bool{}
		for _, n := range f.inputs {
			direct[n] = true
		}
		// tainted names: inputs plus whatever is assigned from them (two passes so order doesn't matter much)
		tainted := map[string]bool{}
		built := map[string]bool{} // strings with input pasted into them (a query or HTML being assembled)
		for n := range direct {
			tainted[n] = true
		}
		for pass := 0; pass < 2; pass++ {
			for i := f.start; i <= f.end; i++ {
				for _, re := range assignRes[lang] {
					m := re.FindStringSubmatch(lines[i])
					if m == nil {
						continue
					}
					rhs := m[2]
					hasSource := source != nil && source.MatchString(rhs)
					n := containsName(rhs, tainted)
					if n == "" && !hasSource {
						continue
					}
					if cl := checkerCleaners[lang]; cl != nil && cl.MatchString(rhs) {
						break
					}
					isBuilt := hasSource && interp.interpolated(lang, rhs, source.FindString(rhs)) ||
						n != "" && (built[n] || interp.interpolated(lang, rhs, n))
					for _, name := range paramNames(m[1]) {
						if name != "_" && name != "err" {
							tainted[name] = true
							if isBuilt {
								built[name] = true
							}
						}
					}
					break
				}
			}
		}
		body := strings.Join(lines[f.start:f.end+1], "\n")
		for _, c := range active {
			l := c.Langs[lang]
			if len(l.requires) > 0 && !anyMatch(l.requires, body) {
				continue
			}
			for i := f.start; i <= f.end; i++ {
				line := lines[i]
				if strings.HasPrefix(strings.TrimSpace(line), comment) {
					continue
				}
				var loc []int
				for _, re := range l.sinks {
					if loc = re.FindStringIndex(line); loc != nil {
						break
					}
				}
				if loc == nil {
					continue
				}
				via, conf := "", "medium"
				if !l.NoInput {
					args := line[loc[0]:]
					if i+1 <= f.end {
						args += " " + lines[i+1] // calls often wrap
					}
					if l.Interpolated {
						via, conf = interpolatedInput(interp, lang, args, source, direct, tainted, built)
					} else if source != nil && source.MatchString(args) {
						via, conf = source.FindString(args), "high"
					} else if n := containsName(args, direct); n != "" {
						via, conf = n, "high"
					} else if n := containsName(args, tainted); n != "" {
						via = n
					}
					if via == "" {
						continue
					}
				}
				if anyMatch(l.lineGuards, line) {
					continue
				}
				before := strings.Join(lines[f.start:i+1], "\n")
				if anyMatch(l.guards, before) {
					continue
				}
				k := key{c.ID, i}
				if found[k] {
					continue
				}
				found[k] = true
				snip := strings.TrimSpace(line)
				if len(snip) > 220 {
					snip = snip[:220] + "…"
				}
				w := c.Weight
				if conf == "medium" {
					w *= 0.6
				}
				out = append(out, Finding{Checker: c.ID, Class: c.Class, Path: name, Line: i + 1, Func: f.name, Via: via,
					Message: c.Message, Snippet: snip, Confidence: conf, Weight: w})
			}
		}
	}
	if lang == "php" {
		out = append(out, wpAuthzFindings(name, src, lines, starts, fns)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Weight != out[j].Weight {
			return out[i].Weight > out[j].Weight
		}
		return out[i].Line < out[j].Line
	})
	if len(out) > maxFindingsPerFile {
		out = out[:maxFindingsPerFile]
	}
	return out
}

// ---------- WordPress: AJAX/REST handlers that change things without checking who's asking ----------

var (
	wpAjaxRe     = regexp.MustCompile(`add_action\(\s*['"]wp_ajax_(nopriv_)?[\w-]+['"]\s*,\s*([^;]+?)\)\s*;`)
	wpQuotedRe   = regexp.MustCompile(`['"](\w+)['"]`)
	wpAuthRe     = regexp.MustCompile(`current_user_can\(|check_ajax_referer\(|wp_verify_nonce\(|check_admin_referer\(|user_can\(`)
	wpWritesRe   = regexp.MustCompile(`\b(update_option|add_option|delete_option|update_site_option|wp_insert_\w+|wp_update_\w+|wp_delete_\w+|wp_trash_post|update_(user|post|term|comment)_meta|add_(user|post)_meta|delete_(user|post)_meta|wp_set_\w+|set_role|add_role|add_cap|wp_create_user|move_uploaded_file|file_put_contents|unlink|wp_mail|switch_theme|activate_plugin)\s*\(|\$wpdb->(query|insert|update|delete|replace)\(`)
	wpRestRe     = regexp.MustCompile(`register_rest_route\(`)
	wpPublicPerm = regexp.MustCompile(`['"]permission_callback['"]\s*=>\s*['"]__return_true['"]`)
	wpWriteVerb  = regexp.MustCompile(`(POST|PUT|PATCH|DELETE|EDITABLE|CREATABLE|DELETABLE)`)
)

const wpAuthzChecker = "wp-missing-authz"

func wpAuthzFindings(name, src string, lines []string, starts []int, fns []fnSpan) []Finding {
	byName := map[string]fnSpan{}
	for _, f := range fns {
		if f.name != "" {
			byName[strings.ToLower(f.name)] = f
		}
	}
	type handler struct {
		nopriv bool
		line   int
	}
	handlers := map[string]*handler{}
	for _, m := range wpAjaxRe.FindAllStringSubmatchIndex(src, -1) {
		cb := wpQuotedRe.FindAllStringSubmatch(src[m[4]:m[5]], -1)
		if len(cb) == 0 {
			continue
		}
		fn := strings.ToLower(cb[len(cb)-1][1])
		h := handlers[fn]
		if h == nil {
			h = &handler{line: lineOf(starts, m[0])}
			handlers[fn] = h
		}
		h.nopriv = h.nopriv || m[2] >= 0
	}
	var out []Finding
	for fn, h := range handlers {
		f, ok := byName[fn]
		if !ok || f.end >= len(lines) {
			continue // defined in another file
		}
		body := strings.Join(lines[f.start:f.end+1], "\n")
		if wpAuthRe.MatchString(body) || !wpWritesRe.MatchString(body) {
			continue
		}
		who, conf, w := "any logged-in user (subscriber and up)", "medium", 3.0
		if h.nopriv {
			who, conf, w = "anyone, without logging in", "high", 4.0
		}
		write := wpWritesRe.FindString(body)
		out = append(out, Finding{Checker: wpAuthzChecker, Class: "missing-auth", Path: name, Line: f.head + 1, Func: f.name,
			Message: "AJAX handler changes data (" + strings.TrimSuffix(write, "(") + ") with no capability or nonce check; callable by " + who,
			Snippet: strings.TrimSpace(lines[f.head]), Confidence: conf, Weight: w})
	}
	for _, m := range wpRestRe.FindAllStringIndex(src, -1) {
		end := min(len(src), m[1]+1200)
		if next := wpRestRe.FindStringIndex(src[m[1]:end]); next != nil {
			end = m[1] + next[0]
		}
		block := src[m[0]:end]
		if wpPublicPerm.MatchString(block) && wpWriteVerb.MatchString(block) {
			l := lineOf(starts, m[0])
			out = append(out, Finding{Checker: wpAuthzChecker, Class: "missing-auth", Path: name, Line: l + 1,
				Message: "REST route that accepts writes is open to everyone (permission_callback __return_true); check what its callback changes",
				Snippet: strings.TrimSpace(lines[l]), Confidence: "medium", Weight: 2.5})
		}
	}
	return out
}

// interpolatedInput finds input pasted into a string in args: a source or input name inside a
// template/concatenation, or a variable that was built that way earlier.
func interpolatedInput(c interpCache, lang, args string, source *regexp.Regexp, direct, tainted, built map[string]bool) (string, string) {
	if source != nil {
		if loc := source.FindStringIndex(args); loc != nil {
			// a source inside the call only counts when it's pasted into a string there
			if src := args[loc[0]:loc[1]]; c.interpolated(lang, args, src) {
				return src, "high"
			}
		}
	}
	for _, id := range identRe.FindAllString(args, -1) {
		switch {
		case built[id]:
			conf := "medium"
			if direct[id] {
				conf = "high"
			}
			return id, conf
		case tainted[id] && c.interpolated(lang, args, id):
			if direct[id] {
				return id, "high"
			}
			return id, "medium"
		}
	}
	return "", ""
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
