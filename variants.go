package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Variant hunting (plan 4b): take a bug somebody already fixed, pull the lines the fix removed,
// and look for other repos that still contain that shape. Candidates go through the normal
// enrich → scan → score pipeline under the "variants" scene, tagged with the advisory they came
// from. Nothing from the fixed repo is ever run; only its diff is read.

const variantScene = "variants"

// VariantPlan is what a fix turned into: the lines it took out and the code searches built
// from them. The UI shows it before a hunt so the queries can be edited.
type VariantPlan struct {
	Ref     string        `json:"ref"`  // normalised input: GHSA id, owner/repo@sha or a PR
	Repo    string        `json:"repo"` // owner/repo that was fixed
	Summary string        `json:"summary,omitempty"`
	CWEs    []string      `json:"cwes,omitempty"`
	Fixes   []string      `json:"fixes"`   // commits / PRs the diff came from
	Removed []VariantLine `json:"removed"` // what the fix took out
	Queries []string      `json:"queries"` // GitHub code searches built from it
	queries []variantQuery
}

type VariantLine struct {
	Path    string `json:"path"`
	Text    string `json:"text"`
	Sink    bool   `json:"sink"`              // matches a checker sink: most likely the vulnerable line itself
	Context bool   `json:"context,omitempty"` // unchanged by the fix: the call a fix that only added a check now guards
	// words ranked for search: identifiers only the pre-fix code has come first, since the
	// fixed version contains the rest too
	words []string
}

type fixRef struct {
	owner, repo, sha string
	pr               int
}

func (f fixRef) full() string { return f.owner + "/" + f.repo }

func (f fixRef) url() string {
	if f.pr > 0 {
		return fmt.Sprintf("https://github.com/%s/pull/%d", f.full(), f.pr)
	}
	return fmt.Sprintf("https://github.com/%s/commit/%s", f.full(), f.sha)
}

var (
	ghsaRe      = regexp.MustCompile(`(?i)\bGHSA(-[23456789cfghjmpqrvwx]{4}){3}\b`)
	commitURLRe = regexp.MustCompile(`github\.com/([\w.-]+)/([\w.-]+)/(?:pull/\d+/)?commits?/([0-9a-f]{7,40})\b`)
	prURLRe     = regexp.MustCompile(`github\.com/([\w.-]+)/([\w.-]+)/pull/(\d+)\b`)
	repoAtShaRe = regexp.MustCompile(`^([\w.-]+)/([\w.-]+)@([0-9a-f]{7,40})$`)
)

// parseFixRefs pulls fix commits out of links, falling back to pull requests when no commit is
// linked. An advisory's references list both, plus plenty that aren't fixes.
func parseFixRefs(links []string) []fixRef {
	var commits, prs []fixRef
	seen := map[string]bool{}
	for _, l := range links {
		if m := commitURLRe.FindStringSubmatch(l); m != nil {
			f := fixRef{owner: m[1], repo: m[2], sha: m[3]}
			if !seen[f.url()] {
				seen[f.url()] = true
				commits = append(commits, f)
			}
			continue
		}
		if m := prURLRe.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[3])
			f := fixRef{owner: m[1], repo: m[2], pr: n}
			if !seen[f.url()] {
				seen[f.url()] = true
				prs = append(prs, f)
			}
		}
	}
	if len(commits) > 0 {
		return commits
	}
	return prs
}

type ghGlobalAdvisory struct {
	GHSAID             string   `json:"ghsa_id"`
	Summary            string   `json:"summary"`
	References         []string `json:"references"`
	SourceCodeLocation string   `json:"source_code_location"`
	CWEs               []struct {
		CWEID string `json:"cwe_id"`
	} `json:"cwes"`
}

type ghPatchFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"`
	Patch    string `json:"patch"`
}

// resolveVariant turns what the user typed into the fix commits to read.
func resolveVariant(ctx context.Context, h *HTTP, input string) (VariantPlan, []fixRef, error) {
	input = strings.TrimSpace(input)
	var plan VariantPlan
	var fixes []fixRef
	switch {
	case ghsaRe.MatchString(input) && !strings.Contains(input, "/"):
		id := "GHSA" + strings.ToLower(ghsaRe.FindString(input)[4:])
		var adv ghGlobalAdvisory
		if _, err := h.GetJSON(ctx, "https://api.github.com/advisories/"+id, &adv); err != nil {
			return plan, nil, err
		}
		plan.Ref, plan.Summary = id, adv.Summary
		for _, c := range adv.CWEs {
			plan.CWEs = append(plan.CWEs, c.CWEID)
		}
		fixes = parseFixRefs(adv.References)
		if len(fixes) == 0 {
			return plan, nil, fmt.Errorf("%s links no fix commit or pull request; paste the fix commit URL instead", id)
		}
	case repoAtShaRe.MatchString(input):
		m := repoAtShaRe.FindStringSubmatch(input)
		fixes = []fixRef{{owner: m[1], repo: m[2], sha: m[3]}}
	default:
		fixes = parseFixRefs([]string{input})
		if len(fixes) == 0 {
			return plan, nil, errors.New("give a GHSA id, a fix commit URL, a pull request URL or owner/repo@sha")
		}
	}
	if len(fixes) > 3 {
		fixes = fixes[:3]
	}
	if plan.Ref == "" {
		plan.Ref = fixes[0].full() + "@" + fixes[0].sha
		if fixes[0].pr > 0 {
			plan.Ref = fmt.Sprintf("%s#%d", fixes[0].full(), fixes[0].pr)
		}
	}
	plan.Repo = fixes[0].full()
	for _, f := range fixes {
		plan.Fixes = append(plan.Fixes, f.url())
	}
	return plan, fixes, nil
}

func fetchPatches(ctx context.Context, h *HTTP, f fixRef) ([]ghPatchFile, error) {
	base := "https://api.github.com/repos/" + url.PathEscape(f.owner) + "/" + url.PathEscape(f.repo)
	if f.pr > 0 {
		var files []ghPatchFile
		_, err := h.GetJSON(ctx, fmt.Sprintf("%s/pulls/%d/files?per_page=100", base, f.pr), &files)
		return files, err
	}
	var c struct {
		Files []ghPatchFile `json:"files"`
	}
	_, err := h.GetJSON(ctx, base+"/commits/"+url.PathEscape(f.sha), &c)
	return c.Files, err
}

// PlanVariant resolves the input, reads the fix diffs and builds the code searches.
func PlanVariant(ctx context.Context, h *HTTP, input string, checkers []*Checker) (VariantPlan, error) {
	plan, fixes, err := resolveVariant(ctx, h, input)
	if err != nil {
		return plan, err
	}
	var files []ghPatchFile
	for _, f := range fixes {
		fs, err := fetchPatches(ctx, h, f)
		if err != nil {
			return plan, fmt.Errorf("%s: %w", f.url(), err)
		}
		files = append(files, fs...)
	}
	plan.Removed = removedLines(files, checkers)
	if len(plan.Removed) == 0 {
		return plan, errors.New("the fix removed no code lines sift can read (only tests, docs or unsupported languages)")
	}
	plan.queries = variantQueries(plan.Removed)
	for _, q := range plan.queries {
		plan.Queries = append(plan.Queries, q.String())
	}
	return plan, nil
}

const maxVariantLines = 40

// removedLines returns the code lines a fix took out and didn't put back as they were: the
// pre-fix shape. When a file's fix only added a check, so nothing it removed reaches a sink,
// the unchanged sink lines around it stand in. Test files, docs and languages without
// checkers are skipped.
func removedLines(files []ghPatchFile, checkers []*Checker) []VariantLine {
	var out []VariantLine
	for _, f := range files {
		lang := checkerLangFor(f.Filename)
		lp := strings.ToLower(f.Filename)
		if lang == "" || f.Patch == "" || checkerSkipPath.MatchString(lp) || isTestPath(lp, path.Base(f.Filename)) {
			continue
		}
		added := map[string]bool{}
		addedWords := map[string]bool{}
		var removed, context []string
		for _, l := range strings.Split(f.Patch, "\n") {
			switch {
			case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"), strings.HasPrefix(l, "@@"):
			case strings.HasPrefix(l, "+"):
				added[normLine(l[1:])] = true
				for _, w := range identRe.FindAllString(stripStrings(l[1:]), -1) {
					addedWords[strings.ToLower(w)] = true
				}
			case strings.HasPrefix(l, "-"):
				removed = append(removed, strings.TrimSpace(l[1:]))
			case strings.HasPrefix(l, " "):
				context = append(context, strings.TrimSpace(l[1:]))
			}
		}
		var lines []VariantLine
		sinks := false
		for _, l := range removed {
			if added[normLine(l)] || !codeLine(l) {
				continue
			}
			vl := VariantLine{Path: f.Filename, Text: l, Sink: sinkLine(lang, l, checkers)}
			sinks = sinks || vl.Sink
			lines = append(lines, vl)
		}
		if !sinks {
			// sink lines the fix left alone first; the other unchanged lines only feed a search
			// when the removed ones are too short to make one
			var rest []VariantLine
			for _, l := range context {
				if !codeLine(l) {
					continue
				}
				if sinkLine(lang, l, checkers) {
					lines = append(lines, VariantLine{Path: f.Filename, Text: l, Sink: true, Context: true})
				} else {
					rest = append(rest, VariantLine{Path: f.Filename, Text: l, Context: true})
				}
			}
			lines = append(lines, rest...)
		}
		for i := range lines {
			lines[i].words = distinctiveWords(lines[i].Text, addedWords)
		}
		out = append(out, lines...)
	}
	// removed sink lines first (the bug itself), then sinks a fix guarded, other removed lines,
	// and unchanged lines last
	rank := func(l VariantLine) int {
		switch {
		case l.Sink && !l.Context:
			return 0
		case l.Sink:
			return 1
		case !l.Context:
			return 2
		}
		return 3
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	if len(out) > maxVariantLines {
		out = out[:maxVariantLines]
	}
	return out
}

func normLine(s string) string { return strings.Join(strings.Fields(s), " ") }

var importLine = regexp.MustCompile(`^(import\b|from\s+\S+\s+import\b|package\b|use\s|require\(|#include|using\s)|^(const|let|var)\s+\w+\s*=\s*require\(`)

// codeLine drops blank lines, comments, lone brackets and imports: nothing to search for.
func codeLine(s string) bool {
	if len(s) < 8 || importLine.MatchString(s) {
		return false
	}
	for _, p := range []string{"//", "#", "/*", "*", "<!--"} {
		if strings.HasPrefix(s, p) {
			return false
		}
	}
	return strings.IndexFunc(s, unicode.IsLetter) >= 0
}

func sinkLine(lang, s string, checkers []*Checker) bool {
	for _, c := range checkers {
		if l := c.Langs[lang]; l != nil && anyMatch(l.sinks, s) {
			return true
		}
	}
	return false
}

// variantStop are names too common to narrow a code search: keywords, and the identifiers
// every handler has.
var variantStop = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`
		const let var function return await async new this self true false null none nil undefined
		if else elif for while in of not and or is def class import from export default try catch
		except finally raise throw with yield lambda pass break continue switch case func type struct
		interface string str int bool float error err echo print array list dict map object
		req res request response ctx args kwargs params param options opts data body query value
		result results item items key name path file dir url uri http https json text content
		config settings get set put post delete patch join split replace format append push length
		len size open close read write exec run call send then catch log logger console
		tolowercase touppercase tostring startswith endswith includes indexof substring slice
		trim strip lower upper encode decode isinstance getattr hasattr urlparse urllib parse
		parsed scheme hostname host port pattern source message prototype resolve normalize
		filename filepath basename dirname existssync exists isfile isdir abspath`) {
		variantStop[w] = true
	}
}

// variantQueries builds up to three code searches, one per distinctive removed line, sink
// lines first. GitHub's code search ignores punctuation, so a query is a few rare words plus
// the language, which finds copied and lightly edited code.
func variantQueries(lines []VariantLine) []variantQuery {
	var out []variantQuery
	seen := map[string]bool{}
	for _, l := range lines {
		if len(l.words) < 2 {
			continue
		}
		q := variantQuery{words: l.words, file: l.Path, used: min(3, len(l.words))}
		if s := q.String(); !seen[s] {
			seen[s] = true
			out = append(out, q)
		}
		if len(out) == 3 {
			break
		}
	}
	return out
}

// variantQuery is a generated search that keeps its spare words, so one that matches too much
// can be narrowed.
type variantQuery struct {
	words []string
	file  string
	used  int
}

func (q variantQuery) String() string { return searchQuery(q.words[:q.used], q.file) }

// variantNarrowAt: a search matching more files than this is too generic to be about one bug.
const variantNarrowAt = 1000

func searchQuery(words []string, file string) string {
	q := strings.Join(words, " ")
	if lang := searchLanguage(file); lang != "" {
		q += " language:" + lang
	}
	return q
}

// distinctiveWords ranks a line's identifiers: ones the fixed code no longer has first, then
// long and mixed-case (resolveWorkspacePath) over short and common. Dotted names are split,
// since search matches the parts anyway.
func distinctiveWords(line string, fixedHas map[string]bool) []string {
	type cand struct {
		w     string
		score int
	}
	var cs []cand
	seen := map[string]bool{}
	for _, id := range identRe.FindAllString(stripStrings(line), -1) {
		id = strings.Trim(id, "$")
		lw := strings.ToLower(id)
		if len(id) < 4 || variantStop[lw] || seen[lw] {
			continue
		}
		seen[lw] = true
		score := len(id)
		if strings.ContainsAny(id, "_") || hasInnerUpper(id) {
			score += 6
		}
		if !fixedHas[lw] {
			score += 10
		}
		cs = append(cs, cand{id, score})
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].score > cs[j].score })
	var out []string
	for _, c := range cs {
		out = append(out, c.w)
	}
	return out
}

func hasInnerUpper(s string) bool {
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

// stripStrings blanks string literal contents: messages and paths in quotes rarely survive a copy.
func stripStrings(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\'', '`':
			i = skipString(s, i) - 1
			b.WriteString(` "" `)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func searchLanguage(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".ts", ".tsx", ".mts", ".cts":
		return "TypeScript"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "JavaScript"
	case ".py":
		return "Python"
	case ".go":
		return "Go"
	case ".php":
		return "PHP"
	}
	return ""
}

type ghCodeItem struct {
	Path       string `json:"path"`
	Repository struct {
		FullName    string  `json:"full_name"`
		HTMLURL     string  `json:"html_url"`
		Description *string `json:"description"`
		Fork        bool    `json:"fork"`
		Owner       struct {
			Login   string `json:"login"`
			HTMLURL string `json:"html_url"`
		} `json:"owner"`
	} `json:"repository"`
}

// SearchCode runs one GitHub code search (default branches only; needs a token) and returns up
// to limit matches.
func (h *HTTP) SearchCode(ctx context.Context, q string, limit int) ([]ghCodeItem, int, error) {
	var all []ghCodeItem
	total := 0
	for page := 1; len(all) < limit && page <= 10; page++ {
		v := url.Values{}
		v.Set("q", q)
		v.Set("per_page", "100")
		v.Set("page", strconv.Itoa(page))
		var out struct {
			TotalCount int          `json:"total_count"`
			Items      []ghCodeItem `json:"items"`
		}
		if _, err := h.GetJSON(ctx, "https://api.github.com/search/code?"+v.Encode(), &out); err != nil {
			return all, total, err
		}
		total = out.TotalCount
		all = append(all, out.Items...)
		if len(out.Items) < 100 {
			break
		}
	}
	if len(all) > limit {
		all = all[:limit]
	}
	return all, total, nil
}

// variantPerQuery caps results per search. A query matching thousands of files isn't
// distinctive; the first couple of hundred are plenty to rank.
const variantPerQuery = 200

// stageVariant plans (or takes) the searches, runs them and files every matching repo as a
// candidate. It returns the candidates' keys, which become the run's working set.
func (a *App) stageVariant(ctx context.Context, h *HTTP, opts RunOpts) (keys []string, found, newCount int) {
	checkers, _ := loadCheckers(filepath.Join(a.base, "checkers"))
	plan, err := PlanVariant(ctx, h, opts.Variant, checkers)
	// your edited searches run as typed; generated ones may be narrowed
	var queries []variantQuery
	for _, q := range opts.VariantQueries {
		if q = strings.TrimSpace(q); q != "" {
			queries = append(queries, variantQuery{words: []string{q}, used: 1})
		}
	}
	if err != nil {
		if len(queries) == 0 {
			a.warnf("variant %s: %v", opts.Variant, err)
			return nil, 0, 0
		}
		a.warnf("variant %s: %v (using your queries anyway)", opts.Variant, err)
		plan.Ref = strings.TrimSpace(opts.Variant)
	}
	if len(queries) == 0 {
		queries = plan.queries
	}
	if len(queries) == 0 {
		a.warnf("variant %s: couldn't build a search from the fix; add one by hand", plan.Ref)
		return nil, 0, 0
	}
	if plan.Summary != "" {
		a.logf("variant of %s: %s", plan.Ref, plan.Summary)
	}
	tag := "variant-of:" + plan.Ref
	self := strings.ToLower(plan.Repo)
	seen := map[string]bool{}
	a.setProgress("variant", 0, len(queries))
	for i, q := range queries {
		if ctx.Err() != nil {
			return
		}
		var items []ghCodeItem
		var total int
		var err error
		for {
			a.logf("[variant] code search: %s", q)
			items, total, err = h.SearchCode(ctx, q.String(), variantPerQuery)
			if err != nil || total <= variantNarrowAt || q.used >= len(q.words) || q.used >= 6 {
				break
			}
			q.used++
			a.logf("[variant] %d files match, too broad; adding a word", total)
		}
		if err != nil {
			a.warnf("[variant] %s: %v", q, err)
		}
		nNew := 0
		for _, it := range items {
			full := it.Repository.FullName
			key := "gh:" + strings.ToLower(full)
			if full == "" || strings.ToLower(full) == self || it.Repository.Fork || seen[key] {
				continue
			}
			seen[key] = true
			keys = append(keys, key)
			if a.upsert(key, func(r *Repo, isNew bool) {
				if isNew {
					r.Source, r.Name, r.URL = "github", full, it.Repository.HTMLURL
					r.Owner, r.OwnerURL = it.Repository.Owner.Login, it.Repository.Owner.HTMLURL
					r.Description, r.GitHubRepo = str(it.Repository.Description), full
					r.PopLabel = "stars"
				}
				r.Categories = addUnique(r.Categories, variantScene)
				r.Queries = addUnique(r.Queries, tag)
			}) {
				nNew++
			}
		}
		found += len(items)
		newCount += nNew
		a.logf("[variant] %d of %d matching files kept, %d new repos", len(items), total, nNew)
		a.setProgress("variant", i+1, len(queries))
	}
	sort.Strings(keys)
	return keys, found, newCount
}
