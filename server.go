package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (a *App) Routes(static fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	mux.HandleFunc("GET /api/state", a.hState)
	mux.HandleFunc("GET /api/repos", a.hRepos)
	mux.HandleFunc("GET /api/repo", a.hRepo)
	mux.HandleFunc("POST /api/repo", a.hRepoUpdate)
	mux.HandleFunc("POST /api/repos/bulk", a.hRepoBulk)
	mux.HandleFunc("POST /api/settings", a.hSettings)
	mux.HandleFunc("POST /api/category", a.hCategoryToggle)
	mux.HandleFunc("POST /api/query", a.hQueryToggle)
	mux.HandleFunc("POST /api/query/test", a.hQueryTest)
	mux.HandleFunc("POST /api/run", a.hRun)
	mux.HandleFunc("POST /api/run/cancel", a.hCancel)
	mux.HandleFunc("POST /api/rescore", a.hRescore)
	mux.HandleFunc("POST /api/defaults", a.hDefaults)
	mux.HandleFunc("GET /api/events", a.hEvents)
	mux.HandleFunc("GET /api/export", a.hExport)
	return guard(mux)
}

// guard blocks DNS rebinding (Host must be local) and cross-site POSTs (custom header required).
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			http.Error(w, "sift only answers on localhost", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Sift") != "1" {
			http.Error(w, "missing X-Sift header", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	return dec.Decode(v)
}

// ---------- state ----------

type catView struct {
	*Category
	Flags         CategoryFlags     `json:"flags"`
	QueryState    map[string]bool   `json:"query_enabled"`
	ExpandedQuery map[string]string `json:"expanded"`
	Repos         int               `json:"repos"`
	Passing       int               `json:"passing"`
}

func (a *App) hState(w http.ResponseWriter, r *http.Request) {
	s := a.settings.Get()
	cats, catErrs := loadCategories(a.dorksDir)
	profiles, profErrs := loadSinkProfiles(a.sinksDir)
	counts := map[string][2]int{}
	totals := map[string]int{}
	a.store.Read(func(repos map[string]*Repo) {
		for _, rp := range repos {
			totals["all"]++
			if rp.Filter.Pass {
				totals["passing"]++
			}
			totals["status:"+rp.Status]++
			for _, c := range rp.Categories {
				v := counts[c]
				v[0]++
				if rp.Filter.Pass {
					v[1]++
				}
				counts[c] = v
			}
		}
	})
	var cv []catView
	for _, c := range cats {
		v := catView{Category: c, Flags: c.Flags(s), QueryState: map[string]bool{}, ExpandedQuery: map[string]string{}}
		for _, q := range c.Queries {
			v.QueryState[q.ID] = !s.DisabledQueries[queryKey(c.ID, q.ID)]
			if c.Source == "github" {
				v.ExpandedQuery[q.ID] = c.FullQuery(q, s)
			}
		}
		v.Repos, v.Passing = counts[c.ID][0], counts[c.ID][1]
		cv = append(cv, v)
	}
	type profView struct {
		*SinkProfile
		Counts [3]int `json:"counts"`
	}
	var pv []profView
	for _, p := range profiles {
		pv = append(pv, profView{p, [3]int{len(p.Surface), len(p.Sinks), len(p.Auth)}})
	}
	_, src := s.TokenAndSource()
	safe := s
	safe.Token = ""
	writeJSON(w, map[string]any{
		"version":      version,
		"base":         a.base,
		"dorks_dir":    a.dorksDir,
		"sinks_dir":    a.sinksDir,
		"settings":     safe,
		"token_source": src,
		"categories":   cv,
		"profiles":     pv,
		"errors":       append(catErrs, profErrs...),
		"progress":     a.Progress(),
		"runs":         a.store.Runs(),
		"totals":       totals,
	})
}

// ---------- repos ----------

type repoSummary struct {
	Key          string         `json:"key"`
	Source       string         `json:"source"`
	Name         string         `json:"name"`
	URL          string         `json:"url"`
	Owner        string         `json:"owner"`
	Description  string         `json:"description"`
	Language     string         `json:"language"`
	Popularity   int            `json:"popularity"`
	PopLabel     string         `json:"pop_label"`
	Categories   []string       `json:"categories"`
	Status       string         `json:"status"`
	HasNotes     bool           `json:"has_notes"`
	Score        *Score         `json:"score"`
	Filter       FilterResult   `json:"filter"`
	PushedAt     *time.Time     `json:"pushed_at,omitempty"`
	LastReply    *time.Time     `json:"last_reply,omitempty"`
	Advisories   int            `json:"advisories"`
	ContactKinds []string       `json:"contact_kinds"`
	CVEPath      string         `json:"cve_path,omitempty"`
	Scanned      bool           `json:"scanned"`
	ScanError    string         `json:"scan_error,omitempty"`
	Sinks        int            `json:"sinks"`
	Surface      int            `json:"surface"`
	Auth         int            `json:"auth"`
	Paired       int            `json:"paired"`
	Classes      map[string]int `json:"classes,omitempty"`
	FirstSeen    time.Time      `json:"first_seen"`
}

func summarize(r *Repo) repoSummary {
	s := repoSummary{
		Key: r.Key, Source: r.Source, Name: r.Name, URL: r.URL, Owner: r.Owner, Description: r.Description,
		Language: r.Language, Popularity: r.Popularity, PopLabel: r.PopLabel, Categories: r.Categories,
		Status: r.Status, HasNotes: r.Notes != "", Score: r.Score, Filter: r.Filter, FirstSeen: r.FirstSeen,
		CVEPath: r.CVEPath,
	}
	if e := r.Enriched; e != nil {
		if !e.PushedAt.IsZero() {
			t := e.PushedAt
			s.PushedAt = &t
		}
		s.LastReply = e.MaintainerLastReply
		s.Advisories = e.Advisories
	}
	seen := map[string]bool{}
	for _, c := range r.Contacts {
		if !seen[c.Kind] && c.Kind != "profile" {
			seen[c.Kind] = true
			s.ContactKinds = append(s.ContactKinds, c.Kind)
		}
	}
	if sc := r.Scan; sc != nil {
		s.Scanned = sc.Error == ""
		s.ScanError = sc.Error
		s.Sinks, s.Surface, s.Auth, s.Classes = sc.SinkHits, sc.SurfaceHits, sc.AuthHits, sc.ByClass
		s.Paired = sc.PairedFiles
	}
	return s
}

func (a *App) hRepos(w http.ResponseWriter, r *http.Request) {
	var out []repoSummary
	a.store.Read(func(repos map[string]*Repo) {
		for _, rp := range repos {
			out = append(out, summarize(rp))
		}
	})
	sort.Slice(out, func(i, j int) bool {
		si, sj := 0.0, 0.0
		if out[i].Score != nil {
			si = out[i].Score.Total
		}
		if out[j].Score != nil {
			sj = out[j].Score.Total
		}
		if si != sj {
			return si > sj
		}
		return out[i].Key < out[j].Key
	})
	if out == nil {
		out = []repoSummary{}
	}
	writeJSON(w, out)
}

func (a *App) hRepo(w http.ResponseWriter, r *http.Request) {
	b, ok := a.store.GetJSON(r.URL.Query().Get("key"))
	if !ok {
		writeErr(w, 404, "no such repo")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (a *App) hRepoUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key    string  `json:"key"`
		Status *string `json:"status"`
		Notes  *string `json:"notes"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Status != nil && !validStatus[*req.Status] {
		writeErr(w, 400, "unknown status")
		return
	}
	found := false
	a.store.With(func(repos map[string]*Repo) {
		rp, ok := repos[req.Key]
		if !ok {
			return
		}
		found = true
		if req.Status != nil {
			rp.Status = *req.Status
		}
		if req.Notes != nil {
			rp.Notes = *req.Notes
		}
		rp.UpdatedAt = time.Now()
	})
	if !found {
		writeErr(w, 404, "no such repo")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) hRepoBulk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string   `json:"action"` // status | delete | delete_filtered
		Keys   []string `json:"keys"`
		Status string   `json:"status"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if a.Progress().Running && strings.HasPrefix(req.Action, "delete") {
		writeErr(w, 409, "stop the run before removing repos")
		return
	}
	n := 0
	a.store.With(func(repos map[string]*Repo) {
		switch req.Action {
		case "status":
			if !validStatus[req.Status] {
				return
			}
			for _, k := range req.Keys {
				if rp, ok := repos[k]; ok {
					rp.Status = req.Status
					n++
				}
			}
		case "delete":
			for _, k := range req.Keys {
				if _, ok := repos[k]; ok {
					delete(repos, k)
					n++
				}
			}
		case "delete_filtered":
			for k, rp := range repos {
				if !rp.Filter.Pass && rp.Status == "new" && rp.Notes == "" {
					delete(repos, k)
					n++
				}
			}
		}
	})
	writeJSON(w, map[string]int{"changed": n})
}

// ---------- settings & toggles ----------

func (a *App) hSettings(w http.ResponseWriter, r *http.Request) {
	var raw map[string]json.RawMessage
	if err := readJSON(r, &raw); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var tokenUpdate *string
	if t, ok := raw["token"]; ok {
		var v string
		_ = json.Unmarshal(t, &v)
		tokenUpdate = &v
		delete(raw, "token")
	}
	delete(raw, "overrides")
	delete(raw, "disabled_queries")
	var err error
	_ = a.settings.Update(func(s *Settings) {
		cur, _ := json.Marshal(s)
		var merged map[string]json.RawMessage
		_ = json.Unmarshal(cur, &merged)
		for k, v := range raw {
			merged[k] = v
		}
		b, _ := json.Marshal(merged)
		next := *s
		if err = json.Unmarshal(b, &next); err != nil {
			return
		}
		next.Overrides, next.DisabledQueries = s.Overrides, s.DisabledQueries
		if tokenUpdate != nil {
			next.Token = strings.TrimSpace(*tokenUpdate)
		}
		if next.Concurrency < 1 {
			next.Concurrency = 1
		}
		if next.Concurrency > 16 {
			next.Concurrency = 16
		}
		if next.GraphQLBatch < 1 || next.GraphQLBatch > 25 {
			next.GraphQLBatch = 8
		}
		*s = next
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	a.Rescore()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) hCategoryToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID    string `json:"id"`
		Field string `json:"field"` // enabled | discover | require | prescore | reset
		Value bool   `json:"value"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = a.settings.Update(func(s *Settings) {
		o := s.Overrides[req.ID]
		v := req.Value
		switch req.Field {
		case "enabled":
			o.Enabled = &v
		case "discover":
			o.Discover = &v
		case "require":
			o.Require = &v
		case "prescore":
			o.Prescore = &v
		case "reset":
			o = CategoryOverride{}
		}
		s.Overrides[req.ID] = o
	})
	a.Rescore()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) hQueryToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Category string `json:"category"`
		Query    string `json:"query"`
		Enabled  bool   `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = a.settings.Update(func(s *Settings) {
		k := queryKey(req.Category, req.Query)
		if req.Enabled {
			delete(s.DisabledQueries, k)
		} else {
			s.DisabledQueries[k] = true
		}
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) hQueryTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Category string `json:"category"`
		Query    string `json:"query"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cats, _ := loadCategories(a.dorksDir)
	var c *Category
	var q *Query
	for _, cc := range cats {
		if cc.ID == req.Category {
			c = cc
			for i := range cc.Queries {
				if cc.Queries[i].ID == req.Query {
					q = &cc.Queries[i]
				}
			}
		}
	}
	if c == nil || q == nil {
		writeErr(w, 404, "query not found — did the file change? Reload the page.")
		return
	}
	s := a.settings.Get()
	token, _ := s.TokenAndSource()
	h := newHTTP(token, func(string, ...any) {})
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	out := map[string]any{}
	var sample []string
	switch c.Source {
	case "github":
		full := c.FullQuery(*q, s)
		res, err := h.searchPage(ctx, full, s.SearchSort, 1)
		if err != nil {
			writeErr(w, 502, err.Error())
			return
		}
		for i, it := range res.Items {
			if i >= 8 {
				break
			}
			sample = append(sample, fmt.Sprintf("%s ★%d", it.FullName, it.StargazersCount))
		}
		out["query"] = full
		out["total"] = res.TotalCount
		if res.TotalCount > 1000 {
			if starsRangeRe.MatchString(full) && s.AutoSplit {
				out["note"] = "Over GitHub's 1000-result cap; sift will split it by stars if your per-query limit is above 1000."
			} else {
				out["note"] = "Over GitHub's 1000-result cap; only the first 1000 are reachable. Add a stars:A..B range to split it."
			}
		}
	case "wordpress":
		qq := *q
		qq.Pages = 1
		res, total, err := h.WPSearch(ctx, c, qq, s)
		if err != nil {
			writeErr(w, 502, err.Error())
			return
		}
		for i, p := range res {
			if i >= 8 {
				break
			}
			sample = append(sample, fmt.Sprintf("%s (%s installs)", p.P.Slug, strconv.Itoa(p.P.ActiveInstalls)))
		}
		out["total"] = total
		out["note"] = fmt.Sprintf("%d of the first 100 pass the install/update limits.", len(res))
	case "jenkins":
		res, total, err := h.JenkinsSearch(ctx, c, *q)
		if err != nil {
			writeErr(w, 502, err.Error())
			return
		}
		sort.Slice(res, func(i, j int) bool { return res[i].P.Popularity > res[j].P.Popularity })
		for i, p := range res {
			if i >= 8 {
				break
			}
			sample = append(sample, fmt.Sprintf("%s (%d installs)", p.P.Name, p.P.Popularity))
		}
		out["total"] = len(res)
		out["note"] = fmt.Sprintf("%d match out of %d plugins.", len(res), total)
	}
	out["sample"] = sample
	writeJSON(w, out)
}

// ---------- runs ----------

func (a *App) hRun(w http.ResponseWriter, r *http.Request) {
	var opts RunOpts
	if err := readJSON(r, &opts); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := a.StartRun(opts); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) hCancel(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"canceled": a.CancelRun()})
}

func (a *App) hRescore(w http.ResponseWriter, r *http.Request) {
	a.Rescore()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) hDefaults(w http.ResponseWriter, r *http.Request) {
	written, err := restoreDefaults(a.base)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if written == nil {
		written = []string{}
	}
	writeJSON(w, map[string]any{"written": written})
}

func (a *App) hEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch, backlog := a.hub.Subscribe()
	defer a.hub.Unsubscribe(ch)
	send := func(e Event) {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	for _, e := range backlog {
		send(e)
	}
	fl.Flush()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			send(e)
			fl.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

// ---------- export ----------

func (a *App) hExport(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope") // passing | all | shortlist
	format := r.URL.Query().Get("format")
	var list []*Repo
	a.store.Read(func(repos map[string]*Repo) {
		for _, rp := range repos {
			switch scope {
			case "all":
			case "shortlist":
				if rp.Status != "shortlist" && rp.Status != "digging" {
					continue
				}
			default:
				if !rp.Filter.Pass {
					continue
				}
			}
			// deep copy via JSON: a shallow copy would still share Enriched/Scan with a running pipeline
			var cp Repo
			if b, err := json.Marshal(rp); err == nil && json.Unmarshal(b, &cp) == nil {
				list = append(list, &cp)
			}
		}
	})
	sort.Slice(list, func(i, j int) bool {
		var si, sj float64
		if list[i].Score != nil {
			si = list[i].Score.Total
		}
		if list[j].Score != nil {
			sj = list[j].Score.Total
		}
		return si > sj
	})
	stamp := time.Now().Format("2006-01-02")
	if format == "json" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sift-%s-%s.json"`, scope, stamp))
		writeJSON(w, list)
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sift-%s-%s.csv"`, scope, stamp))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"score", "name", "source", "url", "categories", "status", "language", "popularity", "last_push", "maintainer_last_reply", "advisories", "contacts", "cve_path", "sink_hits", "surface_hits", "auth_hits", "top_classes", "filtered_out_because", "notes"})
	for _, rp := range list {
		sm := summarize(rp)
		score := ""
		if rp.Score != nil {
			score = strconv.FormatFloat(rp.Score.Total, 'f', 1, 64)
		}
		var contacts []string
		for _, c := range rp.Contacts {
			if c.Kind != "profile" {
				contacts = append(contacts, c.Kind+": "+c.Value)
			}
		}
		var classes []string
		for k, v := range sm.Classes {
			classes = append(classes, fmt.Sprintf("%s=%d", k, v))
		}
		sort.Strings(classes)
		ts := func(t *time.Time) string {
			if t == nil {
				return ""
			}
			return t.Format("2006-01-02")
		}
		_ = cw.Write([]string{
			score, rp.Name, rp.Source, rp.URL, strings.Join(rp.Categories, " "), rp.Status, rp.Language,
			strconv.Itoa(rp.Popularity), ts(sm.PushedAt), ts(sm.LastReply), strconv.Itoa(sm.Advisories),
			strings.Join(contacts, "; "), rp.CVEPath, strconv.Itoa(sm.Sinks), strconv.Itoa(sm.Surface), strconv.Itoa(sm.Auth),
			strings.Join(classes, " "), strings.Join(rp.Filter.Reasons, "; "), rp.Notes,
		})
	}
	cw.Flush()
}
