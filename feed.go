package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Variant feed (plan 4c): once a day, newly published advisories whose bug class sift's
// checkers know become variant hunts on their own. Each one goes through the same planning as
// a hand-started hunt (read the fix diff, build code searches), and only fixes that touch a
// line a checker would flag are hunted. Nothing from the advisory's repo is ever run.

const (
	feedEvery     = 24 * time.Hour
	feedFirstDays = 7   // how far back the very first check looks
	feedKeep      = 400 // advisories remembered for the panel and for dedupe
	feedPerQuery  = 100 // matches kept per code search; lower than a hand hunt's, there are many
	feedMetaKey   = "variant_feed"
)

// classCWEs maps a checker class to the CWEs an advisory about that class carries.
var classCWEs = map[string][]string{
	"path-traversal": {"22", "23", "36", "73"},
	"cmd-exec":       {"77", "78", "88"},
	"code-eval":      {"94", "95"},
	"ssrf":           {"918"},
	"sqli":           {"89"},
	"xss":            {"79"},
}

// feedEcosystems are the package ecosystems whose languages have checkers.
var feedEcosystems = map[string]bool{"npm": true, "pip": true, "go": true, "composer": true}

// feedSceneRe marks advisories in the scenes sift watches; those are hunted first, since their
// siblings are the repos sift ranks best.
var feedSceneRe = regexp.MustCompile(`(?i)\bmcp\b|model context protocol|\bagents?\b|\bllm|langchain|openai|wordpress|\bwp-|jenkins`)

type FeedItem struct {
	GHSA      string    `json:"ghsa"`
	URL       string    `json:"url"`
	Summary   string    `json:"summary"`
	Package   string    `json:"package,omitempty"`
	Ecosystem string    `json:"ecosystem,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	Class     string    `json:"class,omitempty"`
	Published time.Time `json:"published"`
	Status    string    `json:"status"` // hunted | skipped
	Reason    string    `json:"reason,omitempty"`
	Queries   []string  `json:"queries,omitempty"`
	Found     int       `json:"found"` // repos the searches turned up
	New       int       `json:"new"`
	Checked   time.Time `json:"checked"`
}

type FeedState struct {
	LastCheck time.Time  `json:"last_check"`
	Items     []FeedItem `json:"items"` // newest check first
}

func (a *App) feedState() FeedState {
	var st FeedState
	if v := a.store.Meta(feedMetaKey); v != "" {
		_ = json.Unmarshal([]byte(v), &st)
	}
	return st
}

func (a *App) saveFeedState(st FeedState) {
	if len(st.Items) > feedKeep {
		st.Items = st.Items[:feedKeep]
	}
	b, _ := json.Marshal(st)
	if err := a.store.SetMeta(feedMetaKey, string(b)); err != nil {
		a.warnf("[feed] saving state: %v", err)
	}
}

// feedLoop starts the daily check when it's due. It looks every half hour, so a laptop that
// slept through the due time catches up soon after waking. A run already in progress just
// pushes the check to the next look.
func (a *App) feedLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute): // let startup and any hand-started run go first
	}
	for {
		a.maybeFeed()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *App) maybeFeed() {
	s := a.settings.Get()
	if token, _ := s.TokenAndSource(); !s.VariantFeed || token == "" {
		return
	}
	if time.Since(a.feedState().LastCheck) < feedEvery {
		return
	}
	if err := a.StartRun(RunOpts{Feed: true}); err == nil {
		a.logf("[feed] daily variant check started")
	}
}

// fetchAdvisories lists reviewed advisories published since the given day with any of the CWEs.
func fetchAdvisories(ctx context.Context, h *HTTP, since time.Time, cwes []string) ([]ghGlobalAdvisory, error) {
	v := url.Values{}
	v.Set("type", "reviewed")
	v.Set("published", ">="+since.UTC().Format("2006-01-02"))
	v.Set("cwes", strings.Join(cwes, ","))
	v.Set("per_page", "100")
	next := "https://api.github.com/advisories?" + v.Encode()
	var all []ghGlobalAdvisory
	for page := 0; next != "" && page < 10; page++ {
		resp, err := h.Do(ctx, "GET", next, nil, "")
		if err != nil {
			return all, err
		}
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			return all, fmt.Errorf("advisories: %d %s", resp.StatusCode, firstLine(b))
		}
		var batch []ghGlobalAdvisory
		err = json.NewDecoder(resp.Body).Decode(&batch)
		resp.Body.Close()
		if err != nil {
			return all, err
		}
		all = append(all, batch...)
		next = nextLink(resp.Header)
	}
	return all, nil
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func nextLink(hd http.Header) string {
	if m := linkNextRe.FindStringSubmatch(hd.Get("Link")); m != nil && strings.HasPrefix(m[1], "https://api.github.com/") {
		return m[1]
	}
	return ""
}

type feedPick struct {
	item FeedItem
	rank int
}

// feedPicks keeps the advisories worth a hunt and ranks them. Ones outside the ecosystems and
// classes sift knows, duplicates and withdrawn ones are dropped without a trace; ones that
// link no fix are returned as skipped, so the panel can say why.
func feedPicks(advs []ghGlobalAdvisory, cweClass map[string]string, seen map[string]bool) (picks []feedPick, skipped []FeedItem) {
	for _, adv := range advs {
		if seen[adv.GHSAID] || adv.WithdrawnAt != nil || strings.HasPrefix(adv.Summary, "Duplicate Advisory") {
			continue
		}
		seen[adv.GHSAID] = true
		it := FeedItem{GHSA: adv.GHSAID, URL: adv.HTMLURL, Summary: adv.Summary, Severity: adv.Severity, Published: adv.PublishedAt}
		for _, v := range adv.Vulnerabilities {
			if v.Package != nil && feedEcosystems[v.Package.Ecosystem] {
				it.Package, it.Ecosystem = v.Package.Name, v.Package.Ecosystem
				break
			}
		}
		for _, c := range adv.CWEs {
			if cl := cweClass[c.CWEID]; cl != "" && (it.Class == "" || it.Class == "xss") {
				it.Class = cl // prefer a server-side class when an advisory lists several
			}
		}
		if it.Ecosystem == "" || it.Class == "" {
			continue
		}
		if len(parseFixRefs(adv.References)) == 0 {
			it.Status, it.Reason = "skipped", "links no fix commit or pull request"
			skipped = append(skipped, it)
			continue
		}
		rank := map[string]int{"critical": 8, "high": 6, "medium": 4, "low": 2}[adv.Severity]
		if it.Class != "xss" {
			rank += 3 // XSS fixes are mostly library internals, which apps don't copy
		}
		if feedSceneRe.MatchString(it.Package + " " + it.Summary) {
			rank += 4
		}
		picks = append(picks, feedPick{it, rank})
	}
	sort.SliceStable(picks, func(i, j int) bool {
		if picks[i].rank != picks[j].rank {
			return picks[i].rank > picks[j].rank
		}
		return picks[i].item.Published.After(picks[j].item.Published)
	})
	return picks, skipped
}

// stageFeed pulls the advisories published since the last check, hunts variants of the best
// ones and returns every candidate's key as the run's working set.
func (a *App) stageFeed(ctx context.Context, h *HTTP, s Settings) (keys []string, found, newCount int) {
	checkers, _ := a.checkers()
	known := map[string]bool{}
	for _, c := range checkers {
		known[c.Class] = true
	}
	cweClass := map[string]string{}
	var cwes []string
	for cl, ids := range classCWEs {
		if known[cl] {
			for _, id := range ids {
				cweClass["CWE-"+id] = cl
				cwes = append(cwes, id)
			}
		}
	}
	if len(cwes) == 0 {
		a.warnf("[feed] no checkers are switched on, so no advisory class to follow")
		return
	}
	sort.Strings(cwes)

	st := a.feedState()
	since := st.LastCheck.Add(-36 * time.Hour) // published dates are by day; overlap, dedupe below
	if st.LastCheck.IsZero() {
		since = time.Now().AddDate(0, 0, -feedFirstDays)
	}
	a.logf("[feed] advisories published since %s", since.Format("2006-01-02"))
	a.setProgress("feed", 0, 1)
	advs, err := fetchAdvisories(ctx, h, since, cwes)
	if err != nil {
		a.warnf("[feed] %v", err)
		return
	}
	seen := map[string]bool{}
	for _, it := range st.Items {
		seen[it.GHSA] = true
	}
	picks, skipped := feedPicks(advs, cweClass, seen)
	now := time.Now()
	record := func(it FeedItem) {
		it.Checked = now
		st.Items = append([]FeedItem{it}, st.Items...)
		a.saveFeedState(st)
	}
	for _, it := range skipped {
		record(it)
	}
	perDay := s.FeedPerDay
	if perDay <= 0 {
		perDay = 8
	}
	a.logf("[feed] %d new advisories, %d worth a look; hunting up to %d", len(advs), len(picks), perDay)
	hunted := 0
	all := map[string]bool{}
	for i, p := range picks {
		it := p.item
		if ctx.Err() != nil {
			return
		}
		a.setProgress("feed", i, len(picks))
		if hunted >= perDay {
			it.Status, it.Reason = "skipped", fmt.Sprintf("past today's %d hunts; hunt it by hand if it looks good", perDay)
			record(it)
			continue
		}
		plan, err := PlanVariant(ctx, h, it.GHSA, checkers)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err != nil:
			it.Status, it.Reason = "skipped", err.Error()
		case !anySink(plan.Removed):
			it.Status, it.Reason = "skipped", "the fix touches no line a checker flags"
		case len(plan.queries) == 0:
			it.Status, it.Reason = "skipped", "couldn't build a code search from the fix"
		}
		if it.Status == "skipped" {
			a.logf("[feed] %s skipped: %s", it.GHSA, it.Reason)
			record(it)
			continue
		}
		a.logf("[feed] %s (%s, %s %s): %s", it.GHSA, it.Class, it.Ecosystem, it.Package, it.Summary)
		k, f, n := a.huntVariant(ctx, h, plan.Ref, plan.Repo, plan.queries, feedPerQuery, "feed", true)
		if ctx.Err() != nil {
			return
		}
		it.Status, it.Queries, it.Found, it.New = "hunted", plan.Queries, len(k), n
		if len(k) == 0 {
			it.Status, it.Reason = "skipped", "every search from the fix was too generic or found nothing"
		}
		record(it)
		hunted++
		found += f
		newCount += n
		for _, key := range k {
			if !all[key] {
				all[key] = true
				keys = append(keys, key)
			}
		}
	}
	st.LastCheck = now
	a.saveFeedState(st)
	a.setProgress("feed", len(picks), len(picks))
	sort.Strings(keys)
	return keys, found, newCount
}

func anySink(lines []VariantLine) bool {
	for _, l := range lines {
		if l.Sink {
			return true
		}
	}
	return false
}

// hFeed shows the feed: whether it's on, when it last looked and what it did with each advisory.
func (a *App) hFeed(w http.ResponseWriter, r *http.Request) {
	s := a.settings.Get()
	st := a.feedState()
	out := map[string]any{"enabled": s.VariantFeed, "per_day": s.FeedPerDay, "items": st.Items}
	if st.Items == nil {
		out["items"] = []FeedItem{}
	}
	if !st.LastCheck.IsZero() {
		out["last_check"] = st.LastCheck
		out["next_check"] = st.LastCheck.Add(feedEvery)
	}
	writeJSON(w, out)
}

func (a *App) hFeedRun(w http.ResponseWriter, r *http.Request) {
	if token, _ := a.settings.Get().TokenAndSource(); token == "" {
		writeErr(w, 400, "the variant feed needs a GitHub token (code search requires one)")
		return
	}
	if err := a.StartRun(RunOpts{Feed: true}); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
