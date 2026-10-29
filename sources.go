package main

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- WordPress plugin directory ----------

type wpPlugin struct {
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	Version          string `json:"version"`
	Author           string `json:"author"`
	AuthorProfile    string `json:"author_profile"`
	ActiveInstalls   int    `json:"active_installs"`
	LastUpdated      string `json:"last_updated"`
	Homepage         string `json:"homepage"`
	ShortDescription string `json:"short_description"`
	DownloadLink     string `json:"download_link"`
	RequiresPHP      any    `json:"requires_php"`
}

type wpQueryResp struct {
	Info struct {
		Page    int `json:"page"`
		Pages   int `json:"pages"`
		Results int `json:"results"`
	} `json:"info"`
	Plugins []wpPlugin `json:"plugins"`
}

func parseWPTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02 3:04pm MST", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

func stripTags(s string) string { return strings.TrimSpace(htmlTagRe.ReplaceAllString(s, "")) }

func (h *HTTP) wpPage(ctx context.Context, q Query, page int) (wpQueryResp, error) {
	v := url.Values{}
	v.Set("action", "query_plugins")
	v.Set("request[per_page]", "100")
	v.Set("request[page]", strconv.Itoa(page))
	for _, f := range []string{"sections", "description", "ratings", "icons", "banners", "screenshots", "versions", "contributors", "compatibility", "tags", "donate_link"} {
		v.Set("request[fields]["+f+"]", "0")
	}
	if q.Search != "" {
		v.Set("request[search]", q.Search)
	}
	if q.Tag != "" {
		v.Set("request[tag]", q.Tag)
	}
	if q.Author != "" {
		v.Set("request[author]", q.Author)
	}
	if q.Browse != "" {
		v.Set("request[browse]", q.Browse)
	}
	var out wpQueryResp
	_, err := h.GetJSON(ctx, "https://api.wordpress.org/plugins/info/1.2/?"+v.Encode(), &out)
	return out, err
}

type wpResult struct {
	P       wpPlugin
	Updated time.Time
}

// WPSearch runs one WordPress query and applies the category's install/update limits.
func (h *HTTP) WPSearch(ctx context.Context, c *Category, q Query, s Settings) ([]wpResult, int, error) {
	pages := q.Pages
	if pages <= 0 {
		pages = 2
	}
	maxDays := c.WordPress.MaxDaysSinceUpdate
	if maxDays <= 0 {
		maxDays = 180
	}
	cutoff := time.Now().AddDate(0, 0, -maxDays)
	var out []wpResult
	total := 0
	for page := 1; page <= pages; page++ {
		r, err := h.wpPage(ctx, q, page)
		if err != nil {
			return out, total, err
		}
		total = r.Info.Results
		for _, p := range r.Plugins {
			if c.WordPress.MinInstalls > 0 && p.ActiveInstalls < c.WordPress.MinInstalls {
				continue
			}
			if c.WordPress.MaxInstalls > 0 && p.ActiveInstalls > c.WordPress.MaxInstalls {
				continue
			}
			t := parseWPTime(p.LastUpdated)
			if !t.IsZero() && t.Before(cutoff) {
				continue
			}
			out = append(out, wpResult{P: p, Updated: t})
		}
		if page >= r.Info.Pages {
			break
		}
	}
	return out, total, nil
}

// ---------- Jenkins update center ----------

type jkPlugin struct {
	Name             string    `json:"name"`
	Title            string    `json:"title"`
	Excerpt          string    `json:"excerpt"`
	Labels           []string  `json:"labels"`
	Popularity       int       `json:"popularity"`
	ReleaseTimestamp time.Time `json:"releaseTimestamp"`
	Version          string    `json:"version"`
	SCM              string    `json:"scm"`
	URL              string    `json:"url"`
	Developers       []struct {
		DeveloperID string `json:"developerId"`
		Name        string `json:"name"`
		Email       string `json:"email"`
	} `json:"developers"`
}

type jkWarning struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Message string `json:"message"`
	URL     string `json:"url"`
}

type jkUpdateCenter struct {
	Plugins  map[string]jkPlugin `json:"plugins"`
	Warnings []jkWarning         `json:"warnings"`
}

type jkCache struct {
	mu   sync.Mutex
	uc   *jkUpdateCenter
	when time.Time
}

var jenkinsCache jkCache

func (h *HTTP) jenkinsUC(ctx context.Context) (*jkUpdateCenter, error) {
	jenkinsCache.mu.Lock()
	defer jenkinsCache.mu.Unlock()
	if jenkinsCache.uc != nil && time.Since(jenkinsCache.when) < 6*time.Hour {
		return jenkinsCache.uc, nil
	}
	var uc jkUpdateCenter
	if _, err := h.GetJSON(ctx, "https://updates.jenkins.io/current/update-center.actual.json", &uc); err != nil {
		return nil, err
	}
	jenkinsCache.uc, jenkinsCache.when = &uc, time.Now()
	return &uc, nil
}

type jkResult struct {
	P          jkPlugin
	Warnings   int
	WarnNote   string
	GitHubRepo string
}

var ghRepoURLRe = regexp.MustCompile(`github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$`)

func githubFromURL(u string) string {
	m := ghRepoURLRe.FindStringSubmatch(strings.TrimSpace(u))
	if m == nil {
		return ""
	}
	return m[1] + "/" + m[2]
}

func (h *HTTP) JenkinsSearch(ctx context.Context, c *Category, q Query) ([]jkResult, int, error) {
	uc, err := h.jenkinsUC(ctx)
	if err != nil {
		return nil, 0, err
	}
	warn := map[string][]string{}
	for _, w := range uc.Warnings {
		if w.Type == "plugin" && strings.HasPrefix(w.ID, "SECURITY-") {
			warn[w.Name] = append(warn[w.Name], w.ID)
		}
	}
	only := map[string]bool{}
	for _, id := range c.Jenkins.OnlyIDs {
		only[strings.TrimSpace(id)] = true
	}
	excl := map[string]bool{}
	for _, id := range c.Jenkins.ExcludeIDs {
		excl[strings.TrimSpace(id)] = true
	}
	var nameRe *regexp.Regexp
	if q.NameRegex != "" {
		nameRe, _ = regexp.Compile(q.NameRegex)
	}
	maxDays := c.Jenkins.MaxDaysSinceRelease
	var out []jkResult
	for _, p := range uc.Plugins {
		if len(only) > 0 && !only[p.Name] {
			continue
		}
		if excl[p.Name] {
			continue
		}
		if c.Jenkins.MinPopularity > 0 && p.Popularity < c.Jenkins.MinPopularity {
			continue
		}
		if c.Jenkins.MaxPopularity > 0 && p.Popularity > c.Jenkins.MaxPopularity {
			continue
		}
		if maxDays > 0 && !p.ReleaseTimestamp.IsZero() && time.Since(p.ReleaseTimestamp) > time.Duration(maxDays)*24*time.Hour {
			continue
		}
		if !q.All {
			if q.Label != "" {
				found := false
				for _, l := range p.Labels {
					if strings.EqualFold(l, q.Label) {
						found = true
					}
				}
				if !found {
					continue
				}
			}
			if nameRe != nil && !nameRe.MatchString(p.Name+" "+p.Title+" "+p.Excerpt) {
				continue
			}
		}
		ws := warn[p.Name]
		note := ""
		if len(ws) > 0 {
			note = strings.Join(ws, ", ")
		}
		out = append(out, jkResult{P: p, Warnings: len(ws), WarnNote: note, GitHubRepo: githubFromURL(p.SCM)})
	}
	return out, len(uc.Plugins), nil
}
