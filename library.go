package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// The library is the four drop-in folders next to sift: dorks/, sinks/, checkers/ and semgrep/.
// Each kind is the bundled files overlaid by the user's: a file in the folder with the same name
// as a bundled one replaces it, any other file is added. The web UI's builders write to the same
// folders, so a file made by hand and one made in the browser are the same thing.

var libKinds = []string{"dorks", "sinks", "checkers", "semgrep"}

const maxLibFile = 256 << 10

type libFile struct {
	Name   string
	Data   []byte
	Origin string // built-in | edited (replaces a bundled file) | yours
}

// overlay returns the effective files of one kind: the bundled ones first, then the user's from
// dir in name order, a user file taking the place of the bundled file with its name.
func overlay(dir, kind string) []libFile {
	var out []libFile
	at := map[string]int{}
	_ = fs.WalkDir(defaultsFS, "defaults/"+kind, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isYAML(p) {
			return nil
		}
		if b, err := defaultsFS.ReadFile(p); err == nil {
			at[path.Base(p)] = len(out)
			out = append(out, libFile{Name: path.Base(p), Data: b, Origin: "built-in"})
		}
		return nil
	})
	if dir == "" {
		return out
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !e.Type().IsRegular() || !isYAML(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if i, ok := at[e.Name()]; ok {
			out[i] = libFile{Name: e.Name(), Data: b, Origin: "edited"}
		} else {
			out = append(out, libFile{Name: e.Name(), Data: b, Origin: "yours"})
		}
	}
	return out
}

// lib is overlay for the app's folders, minus the files switched off in the UI. Dork files are
// switched off per scene (Settings.Overrides) instead, so they're always all here.
func (a *App) lib(kind string) []libFile {
	off := a.settings.Get().DisabledFiles
	var out []libFile
	for _, f := range overlay(filepath.Join(a.base, kind), kind) {
		if kind == "dorks" || !off[kind+"/"+f.Name] {
			out = append(out, f)
		}
	}
	return out
}

func (a *App) categories() ([]*Category, []LoadError)      { return parseCategories(a.lib("dorks")) }
func (a *App) sinkProfiles() ([]*SinkProfile, []LoadError) { return parseSinkProfiles(a.lib("sinks")) }
func (a *App) checkers() ([]*Checker, []LoadError)         { return parseCheckers(a.lib("checkers")) }

// pruneDefaultCopies removes files that are byte-for-byte copies of a bundled file. Older
// versions copied the bundled dorks and sinks into the folders on first start; a copy would
// shadow every later improvement to the bundled file.
func pruneDefaultCopies(base string) int {
	n := 0
	for _, kind := range libKinds {
		dir := filepath.Join(base, kind)
		for _, f := range overlay(dir, kind) {
			if f.Origin != "edited" {
				continue
			}
			b, err := defaultsFS.ReadFile("defaults/" + kind + "/" + f.Name)
			if err == nil && bytes.Equal(normalizeEOL(b), normalizeEOL(f.Data)) && os.Remove(filepath.Join(dir, f.Name)) == nil {
				n++
			}
		}
	}
	return n
}

func normalizeEOL(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }

// ---------- names and validation ----------

var libNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}\.ya?ml$`)

// libFileName turns what the UI sent into a safe file name: lowercase letters, digits, - and _,
// ending in .yaml. No separators or dots, so it can't leave the folder.
func libFileName(kind, name string) (string, error) {
	known := false
	for _, k := range libKinds {
		known = known || k == kind
	}
	if !known {
		return "", fmt.Errorf("unknown kind %q", kind)
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if !libNameRe.MatchString(name) {
		name = strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
		name = strings.TrimLeft(slugID(name), "_-") + ".yaml"
	}
	if !libNameRe.MatchString(name) {
		return "", fmt.Errorf("give it a name (letters, digits, - and _)")
	}
	return name, nil
}

// validateLib checks a file the way the run would load it, next to the other files of its kind
// (a dork id may not clash with another file's). Semgrep rule files only get a structural check.
func (a *App) validateLib(kind, name string, data []byte) error {
	if len(data) > maxLibFile {
		return fmt.Errorf("file is over %d KB", maxLibFile>>10)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("file is empty")
	}
	files := []libFile{}
	for _, f := range overlay(filepath.Join(a.base, kind), kind) {
		if f.Name != name {
			files = append(files, f)
		}
	}
	files = append(files, libFile{Name: name, Data: data, Origin: "yours"})
	var errs []LoadError
	switch kind {
	case "dorks":
		_, errs = parseCategories(files)
	case "sinks":
		_, errs = parseSinkProfiles(files)
	case "checkers":
		_, errs = parseCheckers(files[len(files)-1:])
	case "semgrep":
		return checkSemgrepFile(data)
	}
	for _, e := range errs {
		if e.File == name {
			return fmt.Errorf("%s", e.Error)
		}
	}
	return nil
}

// checkSemgrepFile makes sure the file is a Semgrep rule list. sift only uses results whose
// metadata.class matches a checker class, so a rule without one would confirm nothing.
func checkSemgrepFile(data []byte) error {
	var f struct {
		Rules []struct {
			ID        string   `yaml:"id"`
			Languages []string `yaml:"languages"`
			Message   string   `yaml:"message"`
			Metadata  struct {
				Class string `yaml:"class"`
			} `yaml:"metadata"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &f); err != nil {
		return err
	}
	if len(f.Rules) == 0 {
		return fmt.Errorf("no rules: the file needs a top-level rules: list")
	}
	for i, r := range f.Rules {
		switch {
		case r.ID == "":
			return fmt.Errorf("rule %d has no id", i+1)
		case len(r.Languages) == 0:
			return fmt.Errorf("rule %s has no languages", r.ID)
		case r.Metadata.Class == "":
			return fmt.Errorf("rule %s has no metadata.class: sift matches it to checker findings by class", r.ID)
		}
	}
	return nil
}

// ---------- HTTP ----------

type libItem struct {
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Origin      string         `json:"origin"`
	Enabled     bool           `json:"enabled"`
	Text        string         `json:"text"`
	Data        map[string]any `json:"data,omitempty"`
	Error       string         `json:"error,omitempty"`
}

func (a *App) hLibrary(w http.ResponseWriter, r *http.Request) {
	s := a.settings.Get()
	cats, _ := a.categories()
	catOn := map[string]bool{}
	for _, c := range cats {
		catOn[c.File] = c.Flags(s).Enabled
	}
	out := map[string][]libItem{}
	for _, kind := range libKinds {
		items := []libItem{}
		for _, f := range overlay(filepath.Join(a.base, kind), kind) {
			it := libItem{Kind: kind, Name: f.Name, Origin: f.Origin, Text: string(f.Data), Enabled: !s.DisabledFiles[kind+"/"+f.Name]}
			if err := yaml.Unmarshal(f.Data, &it.Data); err != nil {
				it.Error = err.Error()
			}
			str := func(k string) string { v, _ := it.Data[k].(string); return strings.TrimSpace(v) }
			it.ID, it.Title, it.Description = str("id"), str("name"), str("description")
			if it.Description == "" {
				it.Description = str("message")
			}
			if kind == "semgrep" {
				rules, _ := it.Data["rules"].([]any)
				it.Description = strconv.Itoa(len(rules)) + " rule(s)"
			}
			if kind == "dorks" {
				on, ok := catOn[f.Name]
				it.Enabled = on
				if !ok && it.Error == "" {
					it.Error = "not loaded: see the errors on Save"
				}
			}
			if it.ID == "" {
				it.ID = slugID(strings.TrimSuffix(f.Name, path.Ext(f.Name)))
			}
			if it.Title == "" {
				it.Title = it.ID
			}
			items = append(items, it)
		}
		sort.SliceStable(items, func(i, j int) bool { return items[i].Title < items[j].Title })
		out[kind] = items
	}
	writeJSON(w, out)
}

func (a *App) hLibrarySave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
		Text string `json:"text"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name, err := libFileName(req.Kind, req.Name)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	data := []byte(req.Text)
	if err := a.validateLib(req.Kind, name, data); err != nil {
		writeErr(w, 400, name+": "+err.Error())
		return
	}
	if err := writeFileAtomic(filepath.Join(a.base, req.Kind, name), data, 0o644); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	a.logf("library: saved %s/%s", req.Kind, name)
	a.Rescore()
	writeJSON(w, map[string]string{"name": name})
}

// hLibraryRemove moves the user's file to the folder's .trash: a bundled file it replaced comes
// back, nothing is lost for good.
func (a *App) hLibraryRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name, err := libFileName(req.Kind, req.Name)
	if err != nil || name != strings.ToLower(req.Name) {
		writeErr(w, 400, "bad file name")
		return
	}
	dir := filepath.Join(a.base, req.Kind)
	if st, err := os.Lstat(filepath.Join(dir, name)); err != nil || !st.Mode().IsRegular() {
		writeErr(w, 404, "that's a bundled file: switch it off instead")
		return
	}
	trash := filepath.Join(dir, ".trash")
	if err := os.MkdirAll(trash, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	dst := filepath.Join(trash, name+"."+strconv.FormatInt(time.Now().Unix(), 10))
	if err := os.Rename(filepath.Join(dir, name), dst); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	a.logf("library: moved %s/%s to %s", req.Kind, name, filepath.Join(req.Kind, ".trash"))
	a.Rescore()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) hLibraryToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind    string `json:"kind"`
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if _, err := libFileName(req.Kind, req.Name); err != nil || req.Kind == "dorks" {
		writeErr(w, 400, "scenes are switched on and off per scene")
		return
	}
	_ = a.settings.Update(func(s *Settings) {
		k := req.Kind + "/" + req.Name
		if req.Enabled {
			delete(s.DisabledFiles, k)
		} else {
			s.DisabledFiles[k] = true
		}
	})
	writeJSON(w, map[string]bool{"ok": true})
}

// hLibraryConvert turns builder form data into YAML ("render") or YAML into form data ("parse").
// Rendering drops comments, so the UI only uses it for files built in the form.
func (a *App) hLibraryConvert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string         `json:"text"`
		Data map[string]any `json:"data"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Data != nil {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(orderedYAML(req.Data)); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, map[string]string{"text": buf.String()})
		return
	}
	var data map[string]any
	if err := yaml.Unmarshal([]byte(req.Text), &data); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"data": data})
}

// yamlKeyOrder puts the keys a person reads first at the top; the rest follow alphabetically.
var yamlKeyOrder = []string{"id", "name", "description", "class", "weight", "message", "source", "enabled", "base",
	"max_results_per_query", "extensions", "skip_paths", "sinks", "contacts", "prescore", "wordpress", "jenkins",
	"arg", "interpolated", "no_input", "guards", "line_guards", "requires", "surface", "auth", "langs", "queries", "q", "note"}

// orderedYAML converts a decoded JSON map into a yaml.Node with a stable, readable key order.
func orderedYAML(v any) *yaml.Node {
	switch t := v.(type) {
	case map[string]any:
		n := &yaml.Node{Kind: yaml.MappingNode}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		rank := func(k string) int {
			for i, o := range yamlKeyOrder {
				if o == k {
					return i
				}
			}
			return len(yamlKeyOrder)
		}
		sort.Slice(keys, func(i, j int) bool {
			if ri, rj := rank(keys[i]), rank(keys[j]); ri != rj {
				return ri < rj
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			if t[k] == nil || t[k] == "" {
				continue // a field left empty in the builder
			}
			n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, orderedYAML(t[k]))
		}
		return n
	case []any:
		n := &yaml.Node{Kind: yaml.SequenceNode}
		for _, e := range t {
			n.Content = append(n.Content, orderedYAML(e))
		}
		return n
	default:
		var n yaml.Node
		_ = n.Encode(t)
		return &n
	}
}

// hLibraryTest tries an unsaved file: a dork query against the live search, a checker or sink
// profile against a pasted code sample, a Semgrep rule file against the sample through Semgrep.
func (a *App) hLibraryTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind  string `json:"kind"`
		Text  string `json:"text"`
		Query string `json:"query"` // dorks: which query to run
		File  string `json:"file"`  // sample file name; its extension picks the language
		Code  string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	f := []libFile{{Name: "test.yaml", Data: []byte(req.Text), Origin: "yours"}}
	fail := func(errs []LoadError) bool {
		if len(errs) > 0 {
			writeErr(w, 400, errs[0].Error)
			return true
		}
		return false
	}
	file := path.Base(strings.ReplaceAll(strings.TrimSpace(req.File), `\`, "/"))
	if file == "." || file == "/" {
		file = "sample.txt"
	}
	switch req.Kind {
	case "dorks":
		cats, errs := parseCategories(f)
		if fail(errs) || len(cats) == 0 {
			return
		}
		c := cats[0]
		q := c.Queries[0]
		for _, qq := range c.Queries {
			if qq.ID == req.Query {
				q = qq
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		out, err := a.testQuery(ctx, c, q)
		if err != nil {
			writeErr(w, 502, err.Error())
			return
		}
		writeJSON(w, out)
	case "checkers":
		cs, errs := parseCheckers(f)
		if fail(errs) || len(cs) == 0 {
			return
		}
		writeJSON(w, testChecker(cs[0], file, req.Code))
	case "sinks":
		ps, errs := parseSinkProfiles(f)
		if fail(errs) || len(ps) == 0 {
			return
		}
		writeJSON(w, map[string]any{"hits": testProfile(ps[0], req.Code)})
	case "semgrep":
		if err := checkSemgrepFile(f[0].Data); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		res, err := a.testSemgrep(r.Context(), f[0].Data, file, req.Code)
		if err != nil {
			writeErr(w, 502, err.Error())
			return
		}
		writeJSON(w, map[string]any{"results": res})
	default:
		writeErr(w, 400, "unknown kind")
	}
}

type sampleHit struct {
	Line  int    `json:"line"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Text  string `json:"text"`
}

// testChecker runs one checker over a code sample. Besides the findings it lists the lines a
// sink matched, so a builder can see "sink found, but no input reached it" and why.
func testChecker(c *Checker, file, code string) map[string]any {
	lang := checkerLangFor(file)
	out := map[string]any{"lang": lang, "findings": []Finding{}, "sinks": []sampleHit{}}
	if lang == "" {
		out["note"] = "No checker language for this file name. Use an extension like .py, .js, .ts, .go or .php."
		return out
	}
	l := c.Langs[lang]
	if l == nil {
		out["note"] = "This checker has no " + lang + " section."
		return out
	}
	var fs []Finding
	for _, f := range runCheckers(file, []byte(code), []*Checker{c}) {
		if f.Checker == c.ID {
			fs = append(fs, f)
		}
	}
	if fs != nil {
		out["findings"] = fs
	}
	var hits []sampleHit
	for i, line := range strings.Split(code, "\n") {
		for j, re := range l.sinks {
			if re.MatchString(line) {
				hits = append(hits, sampleHit{Line: i + 1, Kind: "sink", Label: l.Sinks[j], Text: strings.TrimSpace(line)})
				break
			}
		}
		for j, re := range l.lineGuards {
			if re.MatchString(line) {
				hits = append(hits, sampleHit{Line: i + 1, Kind: "line guard", Label: l.LineGuards[j], Text: strings.TrimSpace(line)})
				break
			}
		}
		for j, re := range l.guards {
			if re.MatchString(line) {
				hits = append(hits, sampleHit{Line: i + 1, Kind: "guard", Label: l.Guards[j], Text: strings.TrimSpace(line)})
				break
			}
		}
	}
	if hits != nil {
		out["sinks"] = hits
	}
	return out
}

// testProfile lists the sample lines each pattern of a sink profile matches.
func testProfile(p *SinkProfile, code string) []sampleHit {
	hits := []sampleHit{}
	for i, line := range strings.Split(code, "\n") {
		for _, g := range []struct {
			kind string
			ps   []Pattern
		}{{"surface", p.Surface}, {"sink", p.Sinks}, {"auth", p.Auth}} {
			for _, pt := range g.ps {
				if pt.re.MatchString(line) {
					hits = append(hits, sampleHit{Line: i + 1, Kind: g.kind, Label: pt.Label, Text: strings.TrimSpace(line)})
				}
			}
		}
	}
	return hits
}

// testSemgrep runs a rule file over the code sample, both written to a fresh temp folder. Semgrep
// only parses the sample; nothing in it runs.
func (a *App) testSemgrep(ctx context.Context, rules []byte, file, code string) ([]semgrepResult, error) {
	bin := semgrepBin(a.settings.Get())
	if bin == "" {
		return nil, fmt.Errorf("semgrep isn't installed")
	}
	if err := os.MkdirAll(a.tmpDir, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(a.tmpDir, "ruletest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0o700); err != nil {
		return nil, err
	}
	rf := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rf, rules, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(src, file), []byte(code), 0o600); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	res, err := runSemgrep(ctx, bin, []string{rf}, src)
	if res == nil {
		res = []semgrepResult{}
	}
	return res, err
}
