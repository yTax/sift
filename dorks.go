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
	"time"

	"gopkg.in/yaml.v3"
)

// ---------- dork files (one category per file) ----------

type WPOpts struct {
	MinInstalls        int `yaml:"min_installs" json:"min_installs"`
	MaxInstalls        int `yaml:"max_installs" json:"max_installs"`
	MaxDaysSinceUpdate int `yaml:"max_days_since_update" json:"max_days_since_update"`
}

type JenkinsOpts struct {
	MinPopularity       int      `yaml:"min_popularity" json:"min_popularity"`
	MaxPopularity       int      `yaml:"max_popularity" json:"max_popularity"`
	MaxDaysSinceRelease int      `yaml:"max_days_since_release" json:"max_days_since_release"`
	OnlyIDs             []string `yaml:"only_ids" json:"only_ids"`
	ExcludeIDs          []string `yaml:"exclude_ids" json:"exclude_ids"`
}

type Query struct {
	ID   string `yaml:"id" json:"id"`
	Note string `yaml:"note" json:"note"`
	// github
	Q string `yaml:"q" json:"q,omitempty"`
	// wordpress
	Search string `yaml:"search" json:"search,omitempty"`
	Tag    string `yaml:"tag" json:"tag,omitempty"`
	Author string `yaml:"author" json:"author,omitempty"`
	Browse string `yaml:"browse" json:"browse,omitempty"`
	Pages  int    `yaml:"pages" json:"pages,omitempty"`
	// jenkins
	Label     string `yaml:"label" json:"label,omitempty"`
	NameRegex string `yaml:"name_regex" json:"name_regex,omitempty"`
	All       bool   `yaml:"all" json:"all,omitempty"`
}

type ContactOpts struct {
	Discover *bool `yaml:"discover" json:"discover"`
	Require  *bool `yaml:"require" json:"require"`
}

type Category struct {
	ID                 string      `yaml:"id" json:"id"`
	Name               string      `yaml:"name" json:"name"`
	Description        string      `yaml:"description" json:"description"`
	Source             string      `yaml:"source" json:"source"` // github | wordpress | jenkins
	Enabled            *bool       `yaml:"enabled" json:"-"`
	Contacts           ContactOpts `yaml:"contacts" json:"-"`
	Prescore           *bool       `yaml:"prescore" json:"-"`
	Base               string      `yaml:"base" json:"base"`
	MaxResultsPerQuery int         `yaml:"max_results_per_query" json:"max_results_per_query"`
	Sinks              []string    `yaml:"sinks" json:"sinks"` // sink profile ids; empty = every profile
	WordPress          WPOpts      `yaml:"wordpress" json:"wordpress"`
	Jenkins            JenkinsOpts `yaml:"jenkins" json:"jenkins"`
	Queries            []Query     `yaml:"queries" json:"queries"`

	File string `yaml:"-" json:"file"`
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// Effective toggles = dork file value, overridden by UI toggles stored in settings.
type CategoryFlags struct {
	Enabled  bool `json:"enabled"`
	Discover bool `json:"discover"`
	Require  bool `json:"require"`
	Prescore bool `json:"prescore"`
	// file defaults so the UI can show "changed from file"
	FileEnabled  bool `json:"file_enabled"`
	FileDiscover bool `json:"file_discover"`
	FileRequire  bool `json:"file_require"`
	FilePrescore bool `json:"file_prescore"`
}

func (c *Category) Flags(s Settings) CategoryFlags {
	defaultContacts := c.Source == "github"
	f := CategoryFlags{
		FileEnabled:  boolOr(c.Enabled, true),
		FileDiscover: boolOr(c.Contacts.Discover, defaultContacts),
		FileRequire:  boolOr(c.Contacts.Require, defaultContacts),
		FilePrescore: boolOr(c.Prescore, true),
	}
	f.Enabled, f.Discover, f.Require, f.Prescore = f.FileEnabled, f.FileDiscover, f.FileRequire, f.FilePrescore
	if o, ok := s.Overrides[c.ID]; ok {
		f.Enabled = boolOr(o.Enabled, f.Enabled)
		f.Discover = boolOr(o.Discover, f.Discover)
		f.Require = boolOr(o.Require, f.Require)
		f.Prescore = boolOr(o.Prescore, f.Prescore)
	}
	if !f.Discover {
		f.Require = false // can't require what we don't look for
	}
	return f
}

func queryKey(cat, q string) string { return cat + "/" + q }

type LoadError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

var idSafe = regexp.MustCompile(`[^a-z0-9_-]+`)

func slugID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = idSafe.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// loadCategories reads the bundled dork files overlaid by the ones in dir (see overlay).
func loadCategories(dir string) ([]*Category, []LoadError) {
	return parseCategories(overlay(dir, "dorks"))
}

func parseCategories(files []libFile) ([]*Category, []LoadError) {
	var cats []*Category
	var errs []LoadError
	seen := map[string]string{}
	for _, f := range files {
		name, b := f.Name, f.Data
		var c Category
		if err := yaml.Unmarshal(b, &c); err != nil {
			errs = append(errs, LoadError{name, err.Error()})
			continue
		}
		c.File = name
		if c.ID == "" {
			c.ID = slugID(strings.TrimSuffix(name, filepath.Ext(name)))
		}
		c.ID = slugID(c.ID)
		if c.Name == "" {
			c.Name = c.ID
		}
		if c.Source == "" {
			c.Source = "github"
		}
		c.Source = strings.ToLower(c.Source)
		if c.Source != "github" && c.Source != "wordpress" && c.Source != "jenkins" {
			errs = append(errs, LoadError{name, fmt.Sprintf("unknown source %q (use github, wordpress or jenkins)", c.Source)})
			continue
		}
		if other, dup := seen[c.ID]; dup {
			errs = append(errs, LoadError{name, fmt.Sprintf("id %q is already used by %s", c.ID, other)})
			continue
		}
		seen[c.ID] = name
		ok := true
		qseen := map[string]bool{}
		for i := range c.Queries {
			q := &c.Queries[i]
			if q.ID == "" {
				q.ID = fmt.Sprintf("q%d", i+1)
			}
			q.ID = slugID(q.ID)
			if qseen[q.ID] {
				q.ID = fmt.Sprintf("%s-%d", q.ID, i+1)
			}
			qseen[q.ID] = true
			switch c.Source {
			case "github":
				if strings.TrimSpace(q.Q) == "" {
					errs = append(errs, LoadError{name, fmt.Sprintf("query %s has no q:", q.ID)})
					ok = false
				}
			case "wordpress":
				if q.Search == "" && q.Tag == "" && q.Author == "" && q.Browse == "" {
					errs = append(errs, LoadError{name, fmt.Sprintf("query %s needs search:, tag:, author: or browse:", q.ID)})
					ok = false
				}
			case "jenkins":
				if q.NameRegex != "" {
					if _, err := regexp.Compile(q.NameRegex); err != nil {
						errs = append(errs, LoadError{name, fmt.Sprintf("query %s name_regex: %v", q.ID, err)})
						ok = false
					}
				}
			}
		}
		if len(c.Queries) == 0 {
			errs = append(errs, LoadError{name, "no queries"})
			ok = false
		}
		if ok {
			cc := c
			cats = append(cats, &cc)
		}
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i].Name < cats[j].Name })
	return cats, errs
}

// expandTemplate replaces {{since}} and {{days_ago:N}} with YYYY-MM-DD dates.
var daysAgoRe = regexp.MustCompile(`\{\{\s*days_ago:(\d+)\s*\}\}`)
var sinceRe = regexp.MustCompile(`\{\{\s*since\s*\}\}`)

func expandTemplate(q string, s Settings) string {
	now := time.Now().UTC()
	q = sinceRe.ReplaceAllString(q, now.AddDate(0, 0, -s.MaxDaysSincePush).Format("2006-01-02"))
	q = daysAgoRe.ReplaceAllStringFunc(q, func(m string) string {
		var n int
		fmt.Sscanf(daysAgoRe.FindStringSubmatch(m)[1], "%d", &n)
		return now.AddDate(0, 0, -n).Format("2006-01-02")
	})
	return strings.Join(strings.Fields(q), " ")
}

func (c *Category) FullQuery(q Query, s Settings) string {
	return expandTemplate(c.Base+" "+q.Q, s)
}

// ---------- sink profiles ----------

type Pattern struct {
	Pattern string  `yaml:"pattern" json:"pattern"`
	Label   string  `yaml:"label" json:"label"`
	Class   string  `yaml:"class" json:"class"`
	Weight  float64 `yaml:"weight" json:"weight"`
	re      *regexp.Regexp
	lits    []string // every match contains one of these (lowercase); nil = no shortcut
}

type SinkProfile struct {
	ID         string    `yaml:"id" json:"id"`
	Name       string    `yaml:"name" json:"name"`
	Extensions []string  `yaml:"extensions" json:"extensions"`
	SkipPaths  []string  `yaml:"skip_paths" json:"skip_paths"`
	Surface    []Pattern `yaml:"surface" json:"surface"`
	Sinks      []Pattern `yaml:"sinks" json:"sinks"`
	Auth       []Pattern `yaml:"auth" json:"auth"`
	File       string    `yaml:"-" json:"file"`
}

// loadSinkProfiles reads the bundled sink profiles overlaid by the ones in dir (see overlay).
func loadSinkProfiles(dir string) ([]*SinkProfile, []LoadError) {
	return parseSinkProfiles(overlay(dir, "sinks"))
}

func parseSinkProfiles(files []libFile) ([]*SinkProfile, []LoadError) {
	var out []*SinkProfile
	var errs []LoadError
	for _, f := range files {
		name, b := f.Name, f.Data
		var p SinkProfile
		if err := yaml.Unmarshal(b, &p); err != nil {
			errs = append(errs, LoadError{name, err.Error()})
			continue
		}
		p.File = name
		if p.ID == "" {
			p.ID = slugID(strings.TrimSuffix(name, filepath.Ext(name)))
		}
		if p.Name == "" {
			p.Name = p.ID
		}
		for i := range p.Extensions {
			x := strings.ToLower(p.Extensions[i])
			if !strings.HasPrefix(x, ".") {
				x = "." + x
			}
			p.Extensions[i] = x
		}
		bad := false
		compile := func(list []Pattern, kind string) {
			for i := range list {
				re, err := regexp.Compile(list[i].Pattern)
				if err != nil {
					errs = append(errs, LoadError{name, fmt.Sprintf("%s pattern %q: %v", kind, list[i].Pattern, err)})
					bad = true
					continue
				}
				list[i].re = re
				list[i].lits = requiredLits(list[i].Pattern)
				if list[i].Weight <= 0 {
					list[i].Weight = 1
				}
				if list[i].Label == "" {
					list[i].Label = list[i].Pattern
				}
			}
		}
		compile(p.Surface, "surface")
		compile(p.Sinks, "sinks")
		compile(p.Auth, "auth")
		if bad {
			continue
		}
		pp := p
		out = append(out, &pp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, errs
}

// ---------- default files ----------

// restoreDefaults writes the bundled templates (_template.yaml: commented examples for writing
// files by hand) that don't exist yet. Never overwrites. The bundled files themselves are read
// straight from the binary (overlay), so they stay current when sift is updated.
func restoreDefaults(base string) (written []string, err error) {
	err = fs.WalkDir(defaultsFS, "defaults", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := strings.TrimPrefix(p, "defaults/")
		if !strings.HasPrefix(path.Base(p), "_") {
			return nil
		}
		dst := filepath.Join(base, filepath.FromSlash(rel))
		if _, err := os.Stat(dst); err == nil {
			return nil
		}
		b, err := defaultsFS.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			return err
		}
		written = append(written, rel)
		return nil
	})
	return written, err
}
