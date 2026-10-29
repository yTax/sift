package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- event hub (live log for the UI) ----------

type Event struct {
	Type  string    `json:"type"` // log | progress | state
	Level string    `json:"level,omitempty"`
	Stage string    `json:"stage,omitempty"`
	Msg   string    `json:"msg,omitempty"`
	Done  int       `json:"done,omitempty"`
	Total int       `json:"total,omitempty"`
	At    time.Time `json:"at"`
}

type Hub struct {
	mu      sync.Mutex
	subs    map[chan Event]bool
	backlog []Event
}

func newHub() *Hub { return &Hub{subs: map[chan Event]bool{}} }

func (h *Hub) Publish(e Event) {
	e.At = time.Now()
	h.mu.Lock()
	if e.Type == "log" {
		h.backlog = append(h.backlog, e)
		if len(h.backlog) > 600 {
			h.backlog = h.backlog[len(h.backlog)-600:]
		}
	}
	for ch := range h.subs {
		select {
		case ch <- e:
		default: // slow client; drop
		}
	}
	h.mu.Unlock()
}

func (h *Hub) Subscribe() (chan Event, []Event) {
	ch := make(chan Event, 256)
	h.mu.Lock()
	h.subs[ch] = true
	bl := append([]Event(nil), h.backlog...)
	h.mu.Unlock()
	return ch, bl
}

func (h *Hub) Unsubscribe(ch chan Event) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

// ---------- app ----------

type Progress struct {
	Running  bool      `json:"running"`
	Stage    string    `json:"stage"`
	Done     int       `json:"done"`
	Total    int       `json:"total"`
	Started  time.Time `json:"started"`
	Canceled bool      `json:"canceled"`
}

type App struct {
	base, dorksDir, sinksDir, dataDir, tmpDir string

	settings *SettingsStore
	store    *Store
	hub      *Hub

	runMu    sync.Mutex
	cancel   context.CancelFunc
	progress Progress
}

func NewApp(base string) (*App, error) {
	a := &App{
		base:     base,
		dorksDir: filepath.Join(base, "dorks"),
		sinksDir: filepath.Join(base, "sinks"),
		dataDir:  filepath.Join(base, "data"),
		tmpDir:   filepath.Join(base, "data", "tmp"),
		hub:      newHub(),
	}
	for _, d := range []string{a.dorksDir, a.sinksDir, a.dataDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	// first start: drop in the bundled dork + sink files
	if entries, _ := os.ReadDir(a.dorksDir); len(entries) == 0 {
		if w, err := restoreDefaults(base); err == nil && len(w) > 0 {
			log.Printf("wrote %d default dork/sink files", len(w))
		}
	}
	os.RemoveAll(a.tmpDir) // leftovers from a crash
	var err error
	if a.settings, err = loadSettings(filepath.Join(a.dataDir, "settings.json")); err != nil {
		return nil, fmt.Errorf("settings.json: %w", err)
	}
	if a.store, err = openStore(filepath.Join(a.dataDir, "state.json")); err != nil {
		return nil, fmt.Errorf("state.json: %w", err)
	}
	a.Rescore() // a run that was killed never reached its final rescore
	return a, nil
}

func (a *App) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	a.hub.Publish(Event{Type: "log", Level: "info", Msg: msg})
}

func (a *App) warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Print("WARN " + msg)
	a.hub.Publish(Event{Type: "log", Level: "warn", Msg: msg})
}

func (a *App) setProgress(stage string, done, total int) {
	a.runMu.Lock()
	a.progress.Stage, a.progress.Done, a.progress.Total = stage, done, total
	a.runMu.Unlock()
	a.hub.Publish(Event{Type: "progress", Stage: stage, Done: done, Total: total})
}

func (a *App) Progress() Progress {
	a.runMu.Lock()
	defer a.runMu.Unlock()
	return a.progress
}

type RunOpts struct {
	Stages     []string `json:"stages"`     // search, enrich, scan
	Categories []string `json:"categories"` // empty = every enabled category
	Force      bool     `json:"force"`      // ignore caches and review status
}

func (a *App) StartRun(opts RunOpts) error {
	a.runMu.Lock()
	defer a.runMu.Unlock()
	if a.progress.Running {
		return errors.New("a run is already in progress")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.progress = Progress{Running: true, Started: time.Now(), Stage: "starting"}
	go a.run(ctx, opts)
	return nil
}

func (a *App) CancelRun() bool {
	a.runMu.Lock()
	defer a.runMu.Unlock()
	if !a.progress.Running || a.cancel == nil {
		return false
	}
	a.progress.Canceled = true
	a.cancel()
	return true
}

// repoFlags combines the flags of every category a repo belongs to.
type repoFlags struct {
	discover, require, prescore, handledByProgram bool
	profiles                                      []*SinkProfile
}

func flagsForRepo(r *Repo, cats map[string]*Category, s Settings, profiles []*SinkProfile) repoFlags {
	var f repoFlags
	requireAll := true
	any := false
	seenProf := map[string]bool{}
	for _, id := range r.Categories {
		c, ok := cats[id]
		if !ok {
			continue
		}
		any = true
		cf := c.Flags(s)
		f.discover = f.discover || cf.Discover
		requireAll = requireAll && cf.Require
		f.prescore = f.prescore || cf.Prescore
		for _, p := range profilesFor(c, profiles) {
			if !seenProf[p.ID] {
				seenProf[p.ID] = true
				f.profiles = append(f.profiles, p)
			}
		}
	}
	if !any {
		requireAll = r.Source == "github"
		f.discover = r.Source == "github"
		f.prescore = true
		f.profiles = profiles
	}
	f.require = requireAll
	f.handledByProgram = (r.Source == "wordpress" || r.Source == "jenkins") && !f.require
	f.prescore = f.prescore && s.ScanEnabled
	return f
}

func (a *App) loadAll() (map[string]*Category, []*Category, []*SinkProfile) {
	cats, _ := loadCategories(a.dorksDir)
	profiles, _ := loadSinkProfiles(a.sinksDir)
	m := map[string]*Category{}
	for _, c := range cats {
		m[c.ID] = c
	}
	return m, cats, profiles
}

// Rescore recomputes filters and scores for every repo, offline.
func (a *App) Rescore() {
	s := a.settings.Get()
	catMap, _, profiles := a.loadAll()
	a.store.With(func(repos map[string]*Repo) {
		for _, r := range repos {
			if r.Scan != nil && r.Scan.HotFiles == nil && len(r.Scan.Hits) > 0 {
				// scanned before pairing existed: rebuild it from the hits we kept
				r.Scan.PairedFiles, r.Scan.PairedWeight, r.Scan.HotFiles = pairHits(r.Scan.Hits)
			}
			f := flagsForRepo(r, catMap, s, profiles)
			r.Filter = applyFilters(r, s, f.require)
			r.Score = computeScore(r, s, f.handledByProgram)
			r.CVEPath, _ = cvePath(r)
		}
	})
}

func (a *App) run(ctx context.Context, opts RunOpts) {
	started := time.Now()
	stages := map[string]bool{}
	for _, st := range opts.Stages {
		stages[st] = true
	}
	if len(stages) == 0 {
		stages = map[string]bool{"search": true, "enrich": true, "scan": true}
	}
	s := a.settings.Get()
	token, tokenSrc := s.TokenAndSource()
	h := newHTTP(token, a.logf)

	allCats, catErrs := loadCategories(a.dorksDir)
	profiles, profErrs := loadSinkProfiles(a.sinksDir)
	for _, e := range append(catErrs, profErrs...) {
		a.warnf("skipping %s: %s", e.File, e.Error)
	}
	catMap := map[string]*Category{}
	for _, c := range allCats {
		catMap[c.ID] = c
	}
	want := map[string]bool{}
	for _, id := range opts.Categories {
		want[id] = true
	}
	var cats []*Category
	for _, c := range allCats {
		if len(want) > 0 {
			if want[c.ID] {
				cats = append(cats, c)
			}
		} else if c.Flags(s).Enabled {
			cats = append(cats, c)
		}
	}
	selected := map[string]bool{}
	var catIDs []string
	for _, c := range cats {
		selected[c.ID] = true
		catIDs = append(catIDs, c.ID)
	}
	var stageList []string
	for _, st := range []string{"search", "enrich", "scan"} {
		if stages[st] {
			stageList = append(stageList, st)
		}
	}
	runID := a.store.AddRun(RunRecord{Started: started, Stages: stageList, Categories: catIDs})
	rec := RunRecord{}
	outcome := "finished"

	defer func() {
		if ctx.Err() != nil {
			outcome = "canceled"
		}
		a.Rescore()
		_ = a.store.SaveNow()
		os.RemoveAll(a.tmpDir)
		a.store.FinishRun(runID, func(r *RunRecord) {
			r.Finished = time.Now()
			r.Found, r.New, r.Scanned = rec.Found, rec.New, rec.Scanned
			r.Outcome = outcome
		})
		a.logf("run %s in %s — %d found, %d new, %d scanned", outcome, time.Since(started).Round(time.Second), rec.Found, rec.New, rec.Scanned)
		a.runMu.Lock()
		a.progress.Running = false
		a.progress.Stage = outcome
		a.cancel = nil
		a.runMu.Unlock()
		a.hub.Publish(Event{Type: "state", Msg: outcome})
	}()

	if len(cats) == 0 {
		a.warnf("no categories selected — enable some on the Dorks page")
		outcome = "nothing to do"
		return
	}
	if token == "" {
		a.warnf("no GitHub token: search is limited to 10 requests/min and enrichment is skipped. Add one in Settings.")
	} else {
		a.logf("using GitHub token from %s", tokenSrc)
	}
	a.logf("run started: %s on %s", strings.Join(stageList, " → "), strings.Join(catIDs, ", "))

	if stages["search"] {
		f, n := a.stageSearch(ctx, h, cats, s)
		rec.Found, rec.New = f, n
		if ctx.Err() != nil {
			return
		}
	}

	// the working set: every stored repo that belongs to a selected category
	var working []string
	a.store.Read(func(repos map[string]*Repo) {
		for k, r := range repos {
			for _, c := range r.Categories {
				if selected[c] {
					working = append(working, k)
					break
				}
			}
		}
	})
	sort.Strings(working)

	if stages["enrich"] {
		a.stageEnrich(ctx, h, working, catMap, profiles, s, opts.Force)
		if ctx.Err() != nil {
			return
		}
	}
	a.Rescore()
	if stages["scan"] {
		rec.Scanned = a.stageScan(ctx, h, working, catMap, profiles, s, opts.Force)
	}
}

// ---------- stage 1: search ----------

func (a *App) upsert(key string, fill func(r *Repo, isNew bool)) bool {
	isNew := false
	a.store.With(func(repos map[string]*Repo) {
		r, ok := repos[key]
		if !ok {
			isNew = true
			r = &Repo{Key: key, Status: "new", FirstSeen: time.Now()}
			repos[key] = r
		}
		r.LastSeen = time.Now()
		fill(r, isNew)
		r.UpdatedAt = time.Now()
	})
	return isNew
}

func (a *App) stageSearch(ctx context.Context, h *HTTP, cats []*Category, s Settings) (found, newCount int) {
	totalQ := 0
	for _, c := range cats {
		for _, q := range c.Queries {
			if !s.DisabledQueries[queryKey(c.ID, q.ID)] {
				totalQ++
			}
		}
	}
	done := 0
	a.setProgress("search", 0, totalQ)
	for _, c := range cats {
		limit := s.MaxResultsPerQuery
		if c.MaxResultsPerQuery > 0 {
			limit = c.MaxResultsPerQuery
		}
		for _, q := range c.Queries {
			if ctx.Err() != nil {
				return
			}
			if s.DisabledQueries[queryKey(c.ID, q.ID)] {
				continue
			}
			qref := c.ID + "/" + q.ID
			switch c.Source {
			case "github":
				full := c.FullQuery(q, s)
				a.logf("[%s] searching: %s", c.ID, full)
				items, total, err := h.SearchAll(ctx, full, s.SearchSort, limit, s.AutoSplit, 0)
				if err != nil {
					a.warnf("[%s] %s: %v", c.ID, q.ID, err)
				}
				nNew := 0
				for _, it := range items {
					it := it
					if a.upsert("gh:"+strings.ToLower(it.FullName), func(r *Repo, isNew bool) {
						r.Source, r.Name, r.URL = "github", it.FullName, it.HTMLURL
						r.Owner, r.OwnerURL = it.Owner.Login, it.Owner.HTMLURL
						r.Description, r.Language = str(it.Description), str(it.Language)
						r.Popularity, r.PopLabel = it.StargazersCount, "stars"
						r.GitHubRepo = it.FullName
						r.Categories = addUnique(r.Categories, c.ID)
						r.Queries = addUnique(r.Queries, qref)
					}) {
						nNew++
					}
				}
				found += len(items)
				newCount += nNew
				a.logf("[%s] %s: %d of %d results kept, %d new", c.ID, q.ID, len(items), total, nNew)
			case "wordpress":
				a.logf("[%s] WordPress query %s", c.ID, q.ID)
				res, total, err := h.WPSearch(ctx, c, q, s)
				if err != nil {
					a.warnf("[%s] %s: %v", c.ID, q.ID, err)
				}
				nNew := 0
				for _, wr := range res {
					p, upd := wr.P, wr.Updated
					if a.upsert("wp:"+p.Slug, func(r *Repo, isNew bool) {
						r.Source, r.Name = "wordpress", p.Slug
						r.URL = "https://wordpress.org/plugins/" + p.Slug + "/"
						r.Owner, r.OwnerURL = stripTags(p.Author), p.AuthorProfile
						r.Description, r.Language = stripTags(p.Name)+" — "+stripTags(p.ShortDescription), "PHP"
						r.Popularity, r.PopLabel = p.ActiveInstalls, "installs"
						r.DownloadURL = p.DownloadLink
						r.Categories = addUnique(r.Categories, c.ID)
						r.Queries = addUnique(r.Queries, qref)
						e := r.Enriched
						if e == nil {
							e = &Enrichment{}
							r.Enriched = e
						}
						e.At, e.PushedAt, e.Version, e.Releases = time.Now(), upd, p.Version, 1
						var cs contactSet
						if p.AuthorProfile != "" {
							cs.add("profile", stripTags(p.Author), p.AuthorProfile, "wordpress.org")
						}
						if p.Homepage != "" {
							cs.scanText(p.Homepage, "plugin homepage")
							cs.add("website", p.Homepage, p.Homepage, "plugin homepage")
						}
						sortContacts(cs.list)
						r.Contacts = cs.list
					}) {
						nNew++
					}
				}
				found += len(res)
				newCount += nNew
				a.logf("[%s] %s: %d kept after install/update limits (%d matched in the directory), %d new", c.ID, q.ID, len(res), total, nNew)
			case "jenkins":
				a.logf("[%s] Jenkins query %s", c.ID, q.ID)
				res, total, err := h.JenkinsSearch(ctx, c, q)
				if err != nil {
					a.warnf("[%s] %s: %v", c.ID, q.ID, err)
				}
				nNew := 0
				for _, jr := range res {
					jr := jr
					if a.upsert("jk:"+jr.P.Name, func(r *Repo, isNew bool) {
						r.Source, r.Name = "jenkins", jr.P.Name
						r.URL = "https://plugins.jenkins.io/" + jr.P.Name + "/"
						if len(jr.P.Developers) > 0 {
							r.Owner = jr.P.Developers[0].DeveloperID
						}
						r.Description = jr.P.Title + " — " + stripTags(jr.P.Excerpt)
						r.Language = "Java"
						r.Popularity, r.PopLabel = jr.P.Popularity, "installs"
						r.GitHubRepo = jr.GitHubRepo
						r.Categories = addUnique(r.Categories, c.ID)
						r.Queries = addUnique(r.Queries, qref)
						e := r.Enriched
						if e == nil {
							e = &Enrichment{}
							r.Enriched = e
						}
						e.PushedAt, e.Version = jr.P.ReleaseTimestamp, jr.P.Version
						if jr.Warnings > e.Advisories {
							e.Advisories = jr.Warnings
						}
						if jr.WarnNote != "" {
							e.AdvisoryNote = "Jenkins advisories: " + jr.WarnNote
						}
						if e.At.IsZero() {
							e.At = time.Now()
						}
					}) {
						nNew++
					}
				}
				found += len(res)
				newCount += nNew
				a.logf("[%s] %s: %d plugins kept (of %d in the update center), %d new", c.ID, q.ID, len(res), total, nNew)
			}
			done++
			a.setProgress("search", done, totalQ)
		}
	}
	return
}

// ---------- stage 2: enrich ----------

type enrichTarget struct {
	key, gh string
	f       repoFlags
}

func (a *App) stageEnrich(ctx context.Context, h *HTTP, working []string, catMap map[string]*Category, profiles []*SinkProfile, s Settings, force bool) {
	var targets []enrichTarget
	refresh := time.Duration(s.RefreshAfterDays) * 24 * time.Hour
	a.store.Read(func(repos map[string]*Repo) {
		for _, k := range working {
			r := repos[k]
			if r.GitHubRepo == "" {
				continue
			}
			if !force && s.SkipReviewed && r.Status != "new" {
				continue
			}
			if !force && r.Enriched != nil && r.Enriched.HeadSHA != "" && r.Enriched.Error == "" && time.Since(r.Enriched.At) < refresh {
				continue
			}
			targets = append(targets, enrichTarget{k, r.GitHubRepo, flagsForRepo(r, catMap, s, profiles)})
		}
	})
	if len(targets) == 0 {
		a.logf("enrich: everything is fresh (refresh window %d days)", s.RefreshAfterDays)
		return
	}
	if h.token == "" {
		a.warnf("enrich: skipped %d repos — GraphQL needs a GitHub token", len(targets))
		return
	}
	a.logf("enrich: fetching metadata for %d repos", len(targets))
	since := time.Now().AddDate(0, 0, -s.MaintainerWindowDays)
	batch := s.GraphQLBatch
	if batch <= 0 {
		batch = 8
	}
	var mu sync.Mutex
	done := 0
	tick := func() { // counts a repo once its metadata is actually stored, not when its goroutine starts
		mu.Lock()
		done++
		d := done
		mu.Unlock()
		a.setProgress("enrich", d, len(targets))
	}
	a.setProgress("enrich", 0, len(targets))

	// GitHub spends about a second per repo answering the GraphQL query no matter how it's
	// batched, so batches run side by side. The per-repo REST checks get their own pool so a
	// slow one never holds up the next batch.
	gqlSem := make(chan struct{}, max(1, s.Concurrency))
	restSem := make(chan struct{}, max(1, 2*s.Concurrency))
	var wg sync.WaitGroup

	for i := 0; i < len(targets); i += batch {
		if ctx.Err() != nil {
			break
		}
		chunk := targets[i:min(i+batch, len(targets))]
		gqlSem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, errs := a.fetchBatch(ctx, h, chunk, since)
			<-gqlSem
			if ctx.Err() != nil {
				return // canceled: leave these repos as they were
			}
			for _, t := range chunk {
				g := res[t.gh]
				if g == nil {
					msg := errs[t.gh]
					a.store.With(func(repos map[string]*Repo) {
						r := repos[t.key]
						if r.Enriched == nil {
							r.Enriched = &Enrichment{}
						}
						r.Enriched.At, r.Enriched.Error = time.Now(), msg
					})
					tick()
					continue
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					restSem <- struct{}{}
					defer func() { <-restSem }()
					a.storeEnrichment(ctx, h, s, t.key, t.f, g)
					tick()
				}()
			}
		}()
	}
	wg.Wait()
	a.setProgress("enrich", len(targets), len(targets))
	a.logf("enrich: done")
}

// fetchBatch runs one GraphQL batch, falling back to one repo at a time if the batch as a whole fails.
func (a *App) fetchBatch(ctx context.Context, h *HTTP, chunk []enrichTarget, since time.Time) (map[string]*gqlRepo, map[string]string) {
	names := make([]string, len(chunk))
	for j, t := range chunk {
		names[j] = t.gh
	}
	res, errs, err := h.EnrichBatch(ctx, names, since)
	if err != nil && len(names) > 1 && ctx.Err() == nil {
		a.warnf("enrich: batch failed (%v), retrying one by one", err)
		res, errs = map[string]*gqlRepo{}, map[string]string{}
		for _, n := range names {
			r1, e1, err1 := h.EnrichBatch(ctx, []string{n}, since)
			if err1 != nil {
				errs[n] = err1.Error()
				continue
			}
			res[n] = r1[n]
			if e1[n] != "" {
				errs[n] = e1[n]
			}
		}
	} else if err != nil {
		errs = map[string]string{}
		for _, n := range names {
			errs[n] = err.Error()
		}
	}
	return res, errs
}

// storeEnrichment adds the REST-only facts (PVR, advisories) to a GraphQL result and saves it.
func (a *App) storeEnrichment(ctx context.Context, h *HTTP, s Settings, key string, f repoFlags, g *gqlRepo) {
	var pvr *bool
	adv := -1
	if s.CheckPVR {
		pvr = h.PVR(ctx, g.NameWithOwner)
	}
	if s.CheckAdvisories {
		adv = h.PublishedAdvisories(ctx, g.NameWithOwner)
	}
	e := buildEnrichment(g, pvr, adv)
	var contacts []Contact
	if f.discover {
		contacts = contactsFromGitHub(g, pvr)
	}
	a.store.With(func(repos map[string]*Repo) {
		r := repos[key]
		prev := r.Enriched
		if r.Source == "jenkins" && prev != nil {
			// keep Jenkins-side facts
			if prev.Advisories > e.Advisories {
				e.Advisories = prev.Advisories
			}
			e.AdvisoryNote = prev.AdvisoryNote
			e.Version = prev.Version
		}
		r.Enriched = e
		if r.Source == "github" {
			r.Description = str(g.Description)
			r.Popularity = g.StargazerCount
			if g.PrimaryLanguage != nil {
				r.Language = g.PrimaryLanguage.Name
			}
		}
		if f.discover {
			r.Contacts = contacts
		} else if r.Source != "wordpress" {
			r.Contacts = nil
		}
	})
}

func buildEnrichment(g *gqlRepo, pvr *bool, adv int) *Enrichment {
	e := &Enrichment{
		At:                time.Now(),
		Archived:          g.IsArchived,
		Fork:              g.IsFork,
		DiskKB:            g.DiskUsage,
		Releases:          g.Releases.TotalCount,
		Tags:              g.Tags.TotalCount,
		HasSecurityPolicy: g.IsSecurityPolicyEnabled,
		SecurityPolicyURL: str(g.SecurityPolicyURL),
		PVR:               pvr,
		OpenIssues:        g.OpenIssues.TotalCount,
		Homepage:          str(g.HomepageURL),
	}
	if g.PushedAt != nil {
		e.PushedAt = *g.PushedAt
	}
	if adv > 0 {
		e.Advisories = adv
	}
	if g.LicenseInfo != nil {
		e.License = g.LicenseInfo.SpdxID
	}
	for _, t := range g.RepositoryTopics.Nodes {
		e.Topics = append(e.Topics, t.Topic.Name)
	}
	if g.DefaultBranchRef != nil {
		e.DefaultBranch = g.DefaultBranchRef.Name
		e.HeadSHA = g.DefaultBranchRef.Target.Oid
		e.RecentCommits = g.DefaultBranchRef.Target.History.TotalCount
	}
	maint := func(assoc string) bool { return assoc == "OWNER" || assoc == "MEMBER" || assoc == "COLLABORATOR" }
	var last time.Time
	consider := func(cs []gqlComment) {
		for _, c := range cs {
			if maint(c.AuthorAssociation) && c.CreatedAt.After(last) {
				last = c.CreatedAt
			}
		}
	}
	for _, n := range g.RecentIssues.Nodes {
		e.IssuesSeen++
		consider(n.Comments.Nodes)
	}
	for _, n := range g.RecentPRs.Nodes {
		e.IssuesSeen++
		consider(n.Comments.Nodes)
	}
	if !last.IsZero() {
		e.MaintainerLastReply = &last
	}
	return e
}

// ---------- stage 3: scan ----------

func (a *App) stageScan(ctx context.Context, h *HTTP, working []string, catMap map[string]*Category, profiles []*SinkProfile, s Settings, force bool) int {
	if !s.ScanEnabled {
		a.logf("scan: turned off in Settings")
		return 0
	}
	if len(profiles) == 0 {
		a.warnf("scan: no sink profiles loaded — add files to the sinks folder")
		return 0
	}
	type target struct {
		key, url, ref string
		strip         bool
		profiles      []*SinkProfile
		diskKB        int
	}
	var targets []target
	a.store.Read(func(repos map[string]*Repo) {
		for _, k := range working {
			r := repos[k]
			if !r.Filter.Pass {
				continue
			}
			if !force && s.SkipReviewed && r.Status != "new" {
				continue
			}
			f := flagsForRepo(r, catMap, s, profiles)
			if !f.prescore || len(f.profiles) == 0 {
				continue
			}
			t := target{key: k, strip: true, profiles: f.profiles}
			switch {
			case r.Source == "wordpress":
				t.url, t.ref = r.DownloadURL, ""
				if r.Enriched != nil {
					t.ref = r.Enriched.Version
				}
			case r.GitHubRepo != "" && r.Enriched != nil && r.Enriched.HeadSHA != "":
				t.ref = r.Enriched.HeadSHA
				t.url = "https://api.github.com/repos/" + r.GitHubRepo + "/zipball/" + t.ref
				t.diskKB = r.Enriched.DiskKB
			default:
				continue
			}
			if t.url == "" {
				continue
			}
			if !force && r.Scan != nil && r.Scan.Ref == t.ref && r.Scan.Error == "" {
				continue
			}
			targets = append(targets, t)
		}
	})
	if len(targets) == 0 {
		a.logf("scan: nothing new to scan")
		return 0
	}
	a.logf("scan: downloading and grepping %d repos (%d at a time)", len(targets), max(1, s.Concurrency))
	maxBytes := int64(s.MaxRepoSizeMB) << 20
	opts := scanOpts{SkipTests: s.SkipTests, MaxFileSize: int64(s.ScanMaxFileKB) << 10, StripPrefix: true}

	var mu sync.Mutex
	done, scanned := 0, 0
	a.setProgress("scan", 0, len(targets))
	sem := make(chan struct{}, max(1, s.Concurrency))
	var wg sync.WaitGroup
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		t := t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var res *ScanResult
			if t.diskKB > 0 && int64(t.diskKB)<<10 > maxBytes*4 {
				res = &ScanResult{At: time.Now(), Ref: t.ref, Error: fmt.Sprintf("repo is %d MB on disk, over the scan limit", t.diskKB>>10)}
			} else {
				path, _, err := h.DownloadToTemp(ctx, t.url, a.tmpDir, maxBytes)
				if err != nil {
					res = &ScanResult{At: time.Now(), Ref: t.ref, Error: err.Error()}
				} else {
					o := opts
					o.Profiles = t.profiles
					r, err := scanZip(path, o)
					os.Remove(path)
					if err != nil {
						res = &ScanResult{At: time.Now(), Ref: t.ref, Error: err.Error()}
					} else {
						r.Ref = t.ref
						res = r
					}
				}
			}
			if ctx.Err() != nil {
				return
			}
			a.store.With(func(repos map[string]*Repo) { repos[t.key].Scan = res })
			mu.Lock()
			done++
			if res.Error == "" {
				scanned++
			}
			d := done
			mu.Unlock()
			if d%25 == 0 {
				a.Rescore() // keep the ranking live during long scans
			}
			if res.Error != "" {
				a.warnf("scan %s: %s", strings.TrimPrefix(strings.TrimPrefix(t.key, "gh:"), "wp:"), res.Error)
			}
			a.setProgress("scan", d, len(targets))
		}()
	}
	wg.Wait()
	a.logf("scan: %d scanned", scanned)
	return scanned
}
