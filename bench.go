package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The bench (plan 17): fixed advisories as an answer key. The code before a fix holds a real
// bug and the code after it doesn't, so every advisory with a fix commit tests the checkers
// twice: do they flag what the fix changed, and do they go quiet once it's fixed? The cases
// live in data/bench (third-party code, so never in the repo); nothing in them is ever run,
// only read by the checkers like any scanned file.

// benchExtraCWEs are classes no checker covers yet. They're collected too, so the report shows
// how often each comes up in real advisories: that's how the next checker gets picked.
var benchExtraCWEs = map[string][]string{
	"deserialization":     {"502"},
	"open-redirect":       {"601"},
	"ssti":                {"1336"},
	"xxe":                 {"611", "776"},
	"prototype-pollution": {"1321"},
	"missing-auth":        {"284", "285", "306", "639", "862", "863"},
	"upload":              {"434"},
}

const (
	benchMaxFiles    = 6
	benchMaxFileSize = 400 << 10
	benchNear        = 3 // lines around a change that still count as "at the change"
)

// benchCWEClass maps "CWE-22" to its class, for every class the bench tracks.
func benchCWEClass() map[string]string {
	m := map[string]string{}
	for _, src := range []map[string][]string{classCWEs, benchExtraCWEs} {
		for cl, ids := range src {
			for _, id := range ids {
				m["CWE-"+id] = cl
			}
		}
	}
	return m
}

type BenchCase struct {
	GHSA      string      `json:"ghsa"`
	Summary   string      `json:"summary"`
	Severity  string      `json:"severity,omitempty"`
	Package   string      `json:"package,omitempty"`
	Ecosystem string      `json:"ecosystem,omitempty"`
	Classes   []string    `json:"classes"`
	Repo      string      `json:"repo"`
	Fix       string      `json:"fix"` // the fix commit's URL
	Published time.Time   `json:"published"`
	Files     []BenchFile `json:"files"`
}

type BenchFile struct {
	Path   string `json:"path"`
	Patch  string `json:"patch"`
	Before string `json:"before"`
	After  string `json:"after"`
}

func (a *App) benchDir() string { return filepath.Join(a.dataDir, "bench") }

var errBenchSkip = errors.New("skip")

// collectBenchCase turns one advisory into a case: its fix commit's modified source files,
// before and after. It returns a reason when the advisory can't become one.
func collectBenchCase(ctx context.Context, h *HTTP, adv ghGlobalAdvisory, cweClass map[string]string) (*BenchCase, error) {
	c := &BenchCase{GHSA: adv.GHSAID, Summary: adv.Summary, Severity: adv.Severity, Published: adv.PublishedAt}
	seen := map[string]bool{}
	for _, w := range adv.CWEs {
		if cl := cweClass[w.CWEID]; cl != "" && !seen[cl] {
			seen[cl] = true
			c.Classes = append(c.Classes, cl)
		}
	}
	for _, v := range adv.Vulnerabilities {
		if v.Package != nil && feedEcosystems[v.Package.Ecosystem] {
			c.Package, c.Ecosystem = v.Package.Name, v.Package.Ecosystem
			break
		}
	}
	if len(c.Classes) == 0 || c.Ecosystem == "" || adv.WithdrawnAt != nil || strings.HasPrefix(adv.Summary, "Duplicate Advisory") {
		return nil, errBenchSkip
	}
	refs := parseFixRefs(adv.References)
	if len(refs) == 0 {
		return nil, errors.New("links no fix")
	}
	f := refs[0]
	base := "https://api.github.com/repos/" + url.PathEscape(f.owner) + "/" + url.PathEscape(f.repo)
	sha := f.sha
	if f.pr > 0 {
		var pr struct {
			Merged         bool   `json:"merged"`
			MergeCommitSHA string `json:"merge_commit_sha"`
		}
		if _, err := h.GetJSON(ctx, fmt.Sprintf("%s/pulls/%d", base, f.pr), &pr); err != nil {
			return nil, err
		}
		if !pr.Merged || pr.MergeCommitSHA == "" {
			return nil, errors.New("fix pull request not merged")
		}
		sha = pr.MergeCommitSHA
	}
	var commit struct {
		SHA     string `json:"sha"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
		Files []ghPatchFile `json:"files"`
	}
	if _, err := h.GetJSON(ctx, base+"/commits/"+url.PathEscape(sha), &commit); err != nil {
		return nil, err
	}
	if len(commit.Parents) == 0 {
		return nil, errors.New("fix commit has no parent")
	}
	c.Repo, c.Fix = f.full(), "https://github.com/"+f.full()+"/commit/"+commit.SHA
	for _, pf := range commit.Files {
		lp := strings.ToLower(pf.Filename)
		if pf.Status != "modified" || pf.Patch == "" || checkerLangFor(pf.Filename) == "" ||
			checkerSkipPath.MatchString(lp) || isTestPath(lp, path.Base(pf.Filename)) {
			continue
		}
		before, err := h.rawFile(ctx, f.owner, f.repo, commit.Parents[0].SHA, pf.Filename)
		if err != nil {
			continue
		}
		after, err := h.rawFile(ctx, f.owner, f.repo, commit.SHA, pf.Filename)
		if err != nil {
			continue
		}
		c.Files = append(c.Files, BenchFile{Path: pf.Filename, Patch: pf.Patch, Before: before, After: after})
		if len(c.Files) == benchMaxFiles {
			break
		}
	}
	if len(c.Files) == 0 {
		return nil, errors.New("fix changes no source file sift reads")
	}
	return c, nil
}

// rawFile reads one file at a commit. raw.githubusercontent.com doesn't count against the API.
func (h *HTTP) rawFile(ctx context.Context, owner, repo, sha, p string) (string, error) {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	u := "https://raw.githubusercontent.com/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/" + url.PathEscape(sha) + "/" + strings.Join(segs, "/")
	resp, err := h.Do(ctx, "GET", u, nil, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: %d", p, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, benchMaxFileSize+1))
	if err != nil {
		return "", err
	}
	if len(b) > benchMaxFileSize {
		return "", fmt.Errorf("%s: too big", p)
	}
	return string(b), nil
}

var benchNameRe = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)

func (a *App) benchCasePath(ghsa string) string {
	return filepath.Join(a.benchDir(), "cases", ghsa+".json.gz")
}

func (a *App) saveBenchCase(c *BenchCase) error {
	if !benchNameRe.MatchString(c.GHSA) {
		return fmt.Errorf("bad id %q", c.GHSA)
	}
	p := a.benchCasePath(c.GHSA)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".case-*")
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(tmp)
	err = json.NewEncoder(zw).Encode(c)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func (a *App) loadBenchCases() ([]*BenchCase, error) {
	paths, err := filepath.Glob(filepath.Join(a.benchDir(), "cases", "GHSA-*.json.gz"))
	if err != nil {
		return nil, err
	}
	var out []*BenchCase
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		zr, err := gzip.NewReader(f)
		if err == nil {
			var c BenchCase
			if json.NewDecoder(zr).Decode(&c) == nil {
				out = append(out, &c)
			}
		}
		f.Close()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Published.After(out[j].Published) })
	return out, nil
}

// benchSkipped remembers advisories that can't become cases, so they aren't fetched again.
func (a *App) benchSkipped() map[string]string {
	m := map[string]string{}
	if b, err := os.ReadFile(filepath.Join(a.benchDir(), "skipped.json")); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (a *App) saveBenchSkipped(m map[string]string) {
	b, _ := json.MarshalIndent(m, "", " ")
	_ = os.MkdirAll(a.benchDir(), 0o755)
	_ = os.WriteFile(filepath.Join(a.benchDir(), "skipped.json"), b, 0o644)
}

func (a *App) haveBenchCase(ghsa string) bool {
	_, err := os.Stat(a.benchCasePath(ghsa))
	return err == nil
}

// addBenchCase files one advisory into the bench unless it's there or known not to fit.
// It reports whether a new case was added.
func (a *App) addBenchCase(ctx context.Context, h *HTTP, adv ghGlobalAdvisory, skipped map[string]string) bool {
	if a.haveBenchCase(adv.GHSAID) || skipped[adv.GHSAID] != "" {
		return false
	}
	c, err := collectBenchCase(ctx, h, adv, benchCWEClass())
	if ctx.Err() != nil {
		return false
	}
	if err != nil {
		if !errors.Is(err, errBenchSkip) {
			skipped[adv.GHSAID] = err.Error()
		}
		return false
	}
	if err := a.saveBenchCase(c); err != nil {
		a.warnf("[bench] %s: %v", c.GHSA, err)
		return false
	}
	return true
}

var benchCollecting sync.Mutex

// BenchCollect adds the advisories published in the last days to the bench, up to max new cases.
func (a *App) BenchCollect(ctx context.Context, days, max int) (int, error) {
	if !benchCollecting.TryLock() {
		return 0, errors.New("already collecting")
	}
	defer benchCollecting.Unlock()
	s := a.settings.Get()
	token, _ := s.TokenAndSource()
	if token == "" {
		return 0, errors.New("collecting needs a GitHub token")
	}
	h := newHTTP(token, a.logf)
	var cwes []string
	for w := range benchCWEClass() {
		cwes = append(cwes, strings.TrimPrefix(w, "CWE-"))
	}
	sort.Strings(cwes)
	since := time.Now().AddDate(0, 0, -days)
	a.logf("[bench] advisories published since %s", since.Format("2006-01-02"))
	advs, err := fetchAdvisoriesPages(ctx, h, since, cwes, 40)
	if err != nil && len(advs) == 0 {
		return 0, err
	}
	skipped := a.benchSkipped()
	var mu sync.Mutex // guards skipped, added and done
	added, done := 0, 0
	jobs := make(chan ghGlobalAdvisory)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for adv := range jobs {
				mu.Lock()
				sk := map[string]string{adv.GHSAID: skipped[adv.GHSAID]}
				mu.Unlock()
				ok := a.addBenchCase(ctx, h, adv, sk)
				mu.Lock()
				if r := sk[adv.GHSAID]; r != "" {
					skipped[adv.GHSAID] = r
				}
				if ok {
					added++
				}
				if done++; done%50 == 0 {
					a.logf("[bench] %d of %d advisories read, %d new cases", done, len(advs), added)
					a.saveBenchSkipped(skipped)
				}
				mu.Unlock()
			}
		}()
	}
	for _, adv := range advs {
		mu.Lock()
		full := added >= max
		mu.Unlock()
		if ctx.Err() != nil || full {
			break
		}
		jobs <- adv
	}
	close(jobs)
	wg.Wait()
	a.saveBenchSkipped(skipped)
	a.logf("[bench] %d new cases", added)
	return added, nil
}

// ---------- scoring ----------

type BenchClass struct {
	Class      string `json:"class"`
	Covered    bool   `json:"covered"`     // a checker exists for this class
	Cases      int    `json:"cases"`       // advisories of this class in the bench
	Caught     int    `json:"caught"`      // flagged at what the fix changed
	Cleared    int    `json:"cleared"`     // caught, and quiet after the fix
	StillAfter int    `json:"still_after"` // caught, and still flagged after the fix: sift doesn't see the fix
	OtherClass int    `json:"other_class"` // missed, but another checker fired there
}

type BenchResult struct {
	GHSA     string   `json:"ghsa"`
	Summary  string   `json:"summary"`
	Package  string   `json:"package,omitempty"`
	Classes  []string `json:"classes"`
	Fix      string   `json:"fix"`
	Result   string   `json:"result"`             // cleared | still | missed | other
	Why      string   `json:"why,omitempty"`      // for a miss: no-sink | no-input | flow (see benchWhy)
	Findings []string `json:"findings,omitempty"` // what fired: checker path:line
	Removed  []string `json:"removed,omitempty"`  // for a miss, the lines the fix took out
}

type BenchReport struct {
	At          time.Time     `json:"at"`
	Fingerprint string        `json:"fingerprint"` // checkers and engine version; a change means a new baseline
	Cases       int           `json:"cases"`
	Caught      int           `json:"caught"`
	Cleared     int           `json:"cleared"`
	CoveredSet  int           `json:"covered_cases"` // cases in a class some checker covers
	Classes     []BenchClass  `json:"classes"`
	Results     []BenchResult `json:"results"`
}

// changedLines reads a unified diff: the lines a fix removed or replaced (old side) and the
// lines it added (new side). A pure insertion marks the line it went after on the old side.
func changedLines(patch string) (old, new map[int]bool) {
	old, new = map[int]bool{}, map[int]bool{}
	hunk := regexp.MustCompile(`^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@`)
	o, n := 0, 0
	for _, l := range strings.Split(patch, "\n") {
		if m := hunk.FindStringSubmatch(l); m != nil {
			o, _ = strconv.Atoi(m[1])
			n, _ = strconv.Atoi(m[2])
			continue
		}
		if o == 0 && n == 0 {
			continue
		}
		switch {
		case strings.HasPrefix(l, "-"):
			old[o] = true
			o++
		case strings.HasPrefix(l, "+"):
			new[n] = true
			old[max(1, o-1)] = true
			n++
		case strings.HasPrefix(l, `\`):
		default:
			o++
			n++
		}
	}
	return old, new
}

// nearChange reports whether a finding's line is at a change: within a few lines of one, or
// in the innermost function around one (a fix adding a check at the top guards a sink lower down).
func nearChange(line int, changed map[int]bool, spans [][2]int) bool {
	for d := -benchNear; d <= benchNear; d++ {
		if changed[line+d] {
			return true
		}
	}
	for _, s := range spans {
		if line >= s[0] && line <= s[1] {
			return true
		}
	}
	return false
}

// touchedSpans returns, 1-based, the innermost function around each changed line.
func touchedSpans(name, src string, changed map[int]bool) [][2]int {
	lang := checkerLangFor(name)
	lines := strings.Split(src, "\n")
	fns := fileFunctions(src, lang, lines, lineStarts(src))
	var out [][2]int
	seen := map[[2]int]bool{}
	for l := range changed {
		best := [2]int{}
		for _, f := range fns {
			s := [2]int{f.head + 1, f.end + 1}
			if l >= s[0] && l <= s[1] && (best[1] == 0 || s[1]-s[0] < best[1]-best[0]) {
				best = s
			}
		}
		if best[1] > 0 && !seen[best] {
			seen[best] = true
			out = append(out, best)
		}
	}
	return out
}

func benchEvalCase(c *BenchCase, checkers []*Checker) BenchResult {
	r := BenchResult{GHSA: c.GHSA, Summary: c.Summary, Package: c.Package, Classes: c.Classes, Fix: c.Fix}
	want := map[string]bool{}
	for _, cl := range c.Classes {
		want[cl] = true
	}
	caught, still, other := false, false, false
	for _, f := range c.Files {
		old, new := changedLines(f.Patch)
		spans := touchedSpans(f.Path, f.Before, old)
		for _, fd := range checkFile(f.Path, []byte(f.Before), checkers) {
			if !nearChange(fd.Line, old, spans) {
				continue
			}
			if want[fd.Class] {
				caught = true
				r.Findings = append(r.Findings, fmt.Sprintf("%s %s:%d", fd.Checker, f.Path, fd.Line))
			} else {
				other = true
			}
		}
		aspans := touchedSpans(f.Path, f.After, new)
		for _, fd := range checkFile(f.Path, []byte(f.After), checkers) {
			if want[fd.Class] && nearChange(fd.Line, new, aspans) {
				still = true
			}
		}
	}
	switch {
	case caught && still:
		r.Result = "still"
	case caught:
		r.Result = "cleared"
	case other:
		r.Result = "other"
	default:
		r.Result = "missed"
	}
	if !caught {
		r.Why = benchWhy(c, checkers, want)
		for _, f := range c.Files {
			for _, l := range strings.Split(f.Patch, "\n") {
				if strings.HasPrefix(l, "-") && !strings.HasPrefix(l, "---") {
					if t := strings.TrimSpace(l[1:]); codeLine(t) && len(r.Removed) < 6 {
						r.Removed = append(r.Removed, f.Path+": "+t)
					}
				}
			}
		}
	}
	return r
}

// benchWhy says why a case was missed, which tells what kind of work would catch it:
//   - no-sink: no checker of the class has a sink near the change. The fix tightened a
//     validator or sanitizer, or the dangerous call is one no checker knows.
//   - no-input: a sink is there, but the function doesn't read input sift recognises (library
//     code whose input is its caller's argument, say).
//   - flow: sink and input are both there and the checker still missed it: an engine gap.
//
// It's "" when no checker covers the class at all.
func benchWhy(c *BenchCase, checkers []*Checker, want map[string]bool) string {
	why := ""
	for _, f := range c.Files {
		lang := checkerLangFor(f.Path)
		lines := strings.Split(f.Before, "\n")
		old, _ := changedLines(f.Patch)
		spans := touchedSpans(f.Path, f.Before, old)
		fns := fileFunctions(f.Before, lang, lines, lineStarts(f.Before))
		fc := &fileCtx{lang: lang, lines: lines, inBlock: blockLines(lines, lang), source: checkerSources[lang], interp: interpCache{}}
		for _, ck := range checkers {
			l := ck.Langs[lang]
			if !want[ck.Class] || l == nil || l.any == nil {
				continue
			}
			if why == "" {
				why = "no-sink"
			}
			for _, sp := range spans {
				if sp[0] < 1 || sp[0] > len(lines) || !l.any.MatchString(strings.Join(lines[sp[0]-1:min(sp[1], len(lines))], "\n")) {
					continue
				}
				if why == "no-sink" {
					why = "no-input"
				}
				for _, fn := range fns {
					if fn.head+1 == sp[0] && fn.end < len(lines) && fn.start <= fn.end && fc.taint(fn, fn.inputs).hasInput {
						return "flow"
					}
				}
			}
		}
	}
	return why
}

// benchFingerprint names the checker set: same fingerprint, same results.
func benchFingerprint(checkers []*Checker) string {
	h := fnv.New64a()
	fmt.Fprintf(h, "engine %d\n", scanEngine)
	for _, c := range checkers {
		b, _ := json.Marshal(c)
		h.Write(b)
	}
	return strconv.FormatUint(h.Sum64(), 36)
}

// BenchScore runs the checkers over every case. Pure CPU, no network.
func BenchScore(cases []*BenchCase, checkers []*Checker) BenchReport {
	rep := BenchReport{At: time.Now(), Fingerprint: benchFingerprint(checkers), Cases: len(cases)}
	covered := map[string]bool{}
	for _, c := range checkers {
		covered[c.Class] = true
	}
	covered["missing-auth"] = true // wp-missing-authz is built in (WordPress AJAX and REST handlers)
	byClass := map[string]*BenchClass{}
	results := make([]BenchResult, len(cases))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, c := range cases {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = benchEvalCase(c, checkers)
		}()
	}
	wg.Wait()
	for _, r := range results {
		anyCovered := false
		for _, cl := range r.Classes {
			bc := byClass[cl]
			if bc == nil {
				bc = &BenchClass{Class: cl, Covered: covered[cl]}
				byClass[cl] = bc
			}
			anyCovered = anyCovered || bc.Covered
			bc.Cases++
			switch r.Result {
			case "cleared":
				bc.Caught++
				bc.Cleared++
			case "still":
				bc.Caught++
				bc.StillAfter++
			case "other":
				bc.OtherClass++
			}
		}
		if anyCovered {
			rep.CoveredSet++
		}
		if r.Result == "cleared" || r.Result == "still" {
			rep.Caught++
		}
		if r.Result == "cleared" {
			rep.Cleared++
		}
	}
	for _, bc := range byClass {
		rep.Classes = append(rep.Classes, *bc)
	}
	sort.Slice(rep.Classes, func(i, j int) bool {
		if rep.Classes[i].Covered != rep.Classes[j].Covered {
			return rep.Classes[i].Covered
		}
		return rep.Classes[i].Cases > rep.Classes[j].Cases
	})
	rank := map[string]int{"still": 0, "missed": 1, "other": 2, "cleared": 3}
	sort.SliceStable(results, func(i, j int) bool { return rank[results[i].Result] < rank[results[j].Result] })
	rep.Results = results
	return rep
}

// benchHistory keeps a line per scored checker set, so the panel can show what a change did.
type benchHistoryEntry struct {
	At          time.Time      `json:"at"`
	Fingerprint string         `json:"fingerprint"`
	Cases       int            `json:"cases"`
	Caught      int            `json:"caught"`
	Cleared     int            `json:"cleared"`
	ByClass     map[string]int `json:"by_class"` // caught per class
}

// RunBench scores the bench, saves the report and adds it to the history.
func (a *App) RunBench() (BenchReport, error) {
	cases, err := a.loadBenchCases()
	if err != nil {
		return BenchReport{}, err
	}
	checkers, _ := a.checkers()
	rep := BenchScore(cases, checkers)
	dir := a.benchDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return rep, err
	}
	b, _ := json.Marshal(rep)
	if err := os.WriteFile(filepath.Join(dir, "report.json"), b, 0o644); err != nil {
		return rep, err
	}
	hist := a.benchHistory()
	e := benchHistoryEntry{At: rep.At, Fingerprint: rep.Fingerprint, Cases: rep.Cases, Caught: rep.Caught, Cleared: rep.Cleared, ByClass: map[string]int{}}
	for _, c := range rep.Classes {
		e.ByClass[c.Class] = c.Caught
	}
	if n := len(hist); n > 0 && hist[n-1].Fingerprint == e.Fingerprint && hist[n-1].Cases == e.Cases {
		hist[n-1] = e
	} else {
		hist = append(hist, e)
	}
	if len(hist) > 100 {
		hist = hist[len(hist)-100:]
	}
	hb, _ := json.MarshalIndent(hist, "", " ")
	_ = os.WriteFile(filepath.Join(dir, "history.json"), hb, 0o644)
	return rep, nil
}

func (a *App) benchHistory() []benchHistoryEntry {
	var h []benchHistoryEntry
	if b, err := os.ReadFile(filepath.Join(a.benchDir(), "history.json")); err == nil {
		_ = json.Unmarshal(b, &h)
	}
	return h
}

// FormatBench prints a report as a table, for the command line.
func FormatBench(rep BenchReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d cases, %d in classes sift checks: caught %d (%.0f%%), %d of them quiet after the fix\n\n",
		rep.Cases, rep.CoveredSet, rep.Caught, pct(rep.Caught, rep.CoveredSet), rep.Cleared)
	fmt.Fprintf(&b, "%-20s %6s %7s %8s %7s %6s\n", "class", "cases", "caught", "cleared", "still", "other")
	for _, c := range rep.Classes {
		name := c.Class
		if !c.Covered {
			name += " (none)"
		}
		fmt.Fprintf(&b, "%-20s %6d %4d %2.0f%% %8d %7d %6d\n", name, c.Cases, c.Caught, pct(c.Caught, c.Cases), c.Cleared, c.StillAfter, c.OtherClass)
	}
	return b.String()
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

// ---------- API ----------

func (a *App) hBench(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"history": a.benchHistory()}
	if b, err := os.ReadFile(filepath.Join(a.benchDir(), "report.json")); err == nil {
		out["report"] = json.RawMessage(b)
	}
	paths, _ := filepath.Glob(filepath.Join(a.benchDir(), "cases", "GHSA-*.json.gz"))
	out["corpus"] = len(paths)
	if benchCollecting.TryLock() {
		benchCollecting.Unlock()
	} else {
		out["collecting"] = true
	}
	writeJSON(w, out)
}

func (a *App) hBenchRun(w http.ResponseWriter, r *http.Request) {
	rep, err := a.RunBench()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, rep)
}

func (a *App) hBenchCollect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Days int `json:"days"`
	}
	_ = readJSON(r, &req)
	if req.Days <= 0 || req.Days > 730 {
		req.Days = 90
	}
	if token, _ := a.settings.Get().TokenAndSource(); token == "" {
		writeErr(w, 400, "collecting needs a GitHub token")
		return
	}
	go func() {
		if _, err := a.BenchCollect(context.Background(), req.Days, 2000); err != nil {
			a.warnf("[bench] %v", err)
			return
		}
		if _, err := a.RunBench(); err != nil {
			a.warnf("[bench] %v", err)
		}
	}()
	writeJSON(w, map[string]bool{"ok": true})
}
