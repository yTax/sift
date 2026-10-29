package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Weights decide how much each score component counts (any positive numbers; they are normalised).
type Weights struct {
	Sinks          float64 `json:"sinks"`
	Surface        float64 `json:"surface"`
	Auth           float64 `json:"auth"`
	History        float64 `json:"history"`
	Responsiveness float64 `json:"responsiveness"`
	Freshness      float64 `json:"freshness"`
	Contact        float64 `json:"contact"`
	CVEPath        float64 `json:"cve_path"`
	Pairing        float64 `json:"pairing"`
}

// CategoryOverride holds UI toggles that override what the dork file says.
// nil means "use the file's value".
type CategoryOverride struct {
	Enabled  *bool `json:"enabled,omitempty"`
	Discover *bool `json:"discover,omitempty"`
	Require  *bool `json:"require,omitempty"`
	Prescore *bool `json:"prescore,omitempty"`
}

type Settings struct {
	Token string `json:"token,omitempty"`

	// Search
	MaxResultsPerQuery int    `json:"max_results_per_query"`
	SearchSort         string `json:"search_sort"` // best-match | updated | stars
	AutoSplit          bool   `json:"auto_split"`

	// Filters
	MaxDaysSincePush          int      `json:"max_days_since_push"`
	MaintainerWindowDays      int      `json:"maintainer_window_days"`
	RequireMaintainerActivity bool     `json:"require_maintainer_activity"`
	RequireReleaseOrTag       bool     `json:"require_release_or_tag"`
	ContactKinds              []string `json:"contact_kinds"` // which kinds count as "has a contact"
	IgnoreList                []string `json:"ignore_list"`   // owner or owner/repo or wp:slug or jk:id
	LanguageAllow             []string `json:"language_allow"`

	// Enrichment
	CheckPVR         bool `json:"check_pvr"`
	CheckAdvisories  bool `json:"check_advisories"`
	RefreshAfterDays int  `json:"refresh_after_days"`
	SkipReviewed     bool `json:"skip_reviewed"`
	GraphQLBatch     int  `json:"graphql_batch"`

	// Pre-score scan
	ScanEnabled   bool `json:"scan_enabled"`
	MaxRepoSizeMB int  `json:"max_repo_size_mb"`
	ScanMaxFileKB int  `json:"scan_max_file_kb"`
	SkipTests     bool `json:"skip_tests"`
	Concurrency   int  `json:"concurrency"`

	Weights      Weights `json:"weights"`
	ScoreCVEPath bool    `json:"score_cve_path"` // score how a finding would become a CVE (CNA on the path or not)

	Overrides       map[string]CategoryOverride `json:"overrides"`
	DisabledQueries map[string]bool             `json:"disabled_queries"` // "category/query"
}

func defaultSettings() Settings {
	return Settings{
		MaxResultsPerQuery:        300,
		SearchSort:                "updated",
		AutoSplit:                 true,
		MaxDaysSincePush:          60,
		MaintainerWindowDays:      90,
		RequireMaintainerActivity: true,
		RequireReleaseOrTag:       true,
		ContactKinds:              []string{"pvr", "security_policy", "email", "discord", "telegram", "matrix", "twitter", "bluesky"},
		CheckPVR:                  true,
		CheckAdvisories:           true,
		RefreshAfterDays:          7,
		SkipReviewed:              true,
		GraphQLBatch:              8,
		ScanEnabled:               true,
		MaxRepoSizeMB:             60,
		ScanMaxFileKB:             512,
		SkipTests:                 true,
		Concurrency:               4,
		Weights: Weights{
			Sinks: 3, Surface: 2, Auth: 2, History: 1.5, Responsiveness: 1.5, Freshness: 1, Contact: 1, CVEPath: 2, Pairing: 3,
		},
		ScoreCVEPath:    true,
		Overrides:       map[string]CategoryOverride{},
		DisabledQueries: map[string]bool{},
	}
}

type SettingsStore struct {
	mu   sync.RWMutex
	path string
	s    Settings
}

func loadSettings(path string) (*SettingsStore, error) {
	st := &SettingsStore{path: path, s: defaultSettings()}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &st.s); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if st.s.Overrides == nil {
		st.s.Overrides = map[string]CategoryOverride{}
	}
	if st.s.DisabledQueries == nil {
		st.s.DisabledQueries = map[string]bool{}
	}
	return st, st.saveLocked()
}

func (st *SettingsStore) Get() Settings {
	st.mu.RLock()
	defer st.mu.RUnlock()
	s := st.s
	// copy maps so callers can't race with writers
	s.Overrides = make(map[string]CategoryOverride, len(st.s.Overrides))
	for k, v := range st.s.Overrides {
		s.Overrides[k] = v
	}
	s.DisabledQueries = make(map[string]bool, len(st.s.DisabledQueries))
	for k, v := range st.s.DisabledQueries {
		s.DisabledQueries[k] = v
	}
	return s
}

func (st *SettingsStore) Update(fn func(s *Settings)) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(&st.s)
	return st.saveLocked()
}

func (st *SettingsStore) saveLocked() error {
	b, err := json.MarshalIndent(st.s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(st.path, b, 0o600)
}

// Token returns the GitHub token and where it came from. Env vars win over the settings file.
func (s Settings) TokenAndSource() (string, string) {
	for _, k := range []string{"SIFT_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, "env " + k
		}
	}
	if s.Token != "" {
		return s.Token, "settings"
	}
	return "", ""
}

// loadDotEnv reads KEY=VALUE lines from path into the environment. Variables that are
// already set win, so a real env var always overrides the file. A missing file is fine.
func loadDotEnv(path string) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if k == "" || v == "" {
			continue
		}
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
