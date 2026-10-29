package main

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

type Contact struct {
	Kind  string `json:"kind"`  // pvr, security_policy, email, discord, telegram, matrix, twitter, bluesky, website, profile
	Value string `json:"value"` // what to show
	URL   string `json:"url,omitempty"`
	Where string `json:"where"` // where it was found
}

type Enrichment struct {
	At                  time.Time  `json:"at"`
	PushedAt            time.Time  `json:"pushed_at"`
	Archived            bool       `json:"archived"`
	Fork                bool       `json:"fork"`
	DefaultBranch       string     `json:"default_branch,omitempty"`
	HeadSHA             string     `json:"head_sha,omitempty"`
	DiskKB              int        `json:"disk_kb"`
	Releases            int        `json:"releases"`
	Tags                int        `json:"tags"`
	Version             string     `json:"version,omitempty"`
	HasSecurityPolicy   bool       `json:"has_security_policy"`
	SecurityPolicyURL   string     `json:"security_policy_url,omitempty"`
	PVR                 *bool      `json:"pvr,omitempty"`
	Advisories          int        `json:"advisories"`
	AdvisoryNote        string     `json:"advisory_note,omitempty"`
	IssuesSeen          int        `json:"issues_seen"` // issues+PRs inspected for maintainer replies
	MaintainerLastReply *time.Time `json:"maintainer_last_reply,omitempty"`
	OpenIssues          int        `json:"open_issues"`
	RecentCommits       int        `json:"recent_commits"`
	Topics              []string   `json:"topics,omitempty"`
	Homepage            string     `json:"homepage,omitempty"`
	License             string     `json:"license,omitempty"`
	Error               string     `json:"error,omitempty"`
}

type Hit struct {
	Path    string  `json:"path"`
	Line    int     `json:"line"`
	Kind    string  `json:"kind"` // surface | sink | auth
	Label   string  `json:"label"`
	Class   string  `json:"class,omitempty"`
	Weight  float64 `json:"weight"`
	Snippet string  `json:"snippet"`
}

type ScanResult struct {
	At            time.Time      `json:"at"`
	Ref           string         `json:"ref"` // sha or version scanned
	Files         int            `json:"files"`
	Bytes         int64          `json:"bytes"`
	SurfaceHits   int            `json:"surface_hits"`
	SinkHits      int            `json:"sink_hits"`
	AuthHits      int            `json:"auth_hits"`
	WeightedSinks float64        `json:"weighted_sinks"`
	ByClass       map[string]int `json:"by_class"`
	Hits          []Hit          `json:"hits,omitempty"`
	Truncated     bool           `json:"truncated"`
	Error         string         `json:"error,omitempty"`
}

type Score struct {
	Total   float64            `json:"total"`
	Parts   map[string]float64 `json:"parts"`
	Partial bool               `json:"partial"` // code parts missing (not scanned)
	At      time.Time          `json:"at"`
}

type FilterResult struct {
	Pass    bool     `json:"pass"`
	Reasons []string `json:"reasons,omitempty"`
}

type Repo struct {
	Key         string `json:"key"`    // gh:owner/repo | wp:slug | jk:id
	Source      string `json:"source"` // github | wordpress | jenkins
	Name        string `json:"name"`
	URL         string `json:"url"`
	Owner       string `json:"owner"`
	OwnerURL    string `json:"owner_url,omitempty"`
	Description string `json:"description,omitempty"`
	Language    string `json:"language,omitempty"`
	Popularity  int    `json:"popularity"`
	PopLabel    string `json:"pop_label"` // stars | installs | popularity
	GitHubRepo  string `json:"github_repo,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`

	Categories []string  `json:"categories"`
	Queries    []string  `json:"queries"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`

	Enriched *Enrichment  `json:"enriched,omitempty"`
	Contacts []Contact    `json:"contacts,omitempty"`
	Scan     *ScanResult  `json:"scan,omitempty"`
	Score    *Score       `json:"score,omitempty"`
	Filter   FilterResult `json:"filter"`
	CVEPath  string       `json:"cve_path,omitempty"` // see cvePath: github-pvr | wordpress-cna | jenkins-cna | mitre | …

	Status    string    `json:"status"` // new | shortlist | digging | reported | skipped
	Notes     string    `json:"notes,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

var validStatus = map[string]bool{"new": true, "shortlist": true, "digging": true, "reported": true, "skipped": true}

type RunRecord struct {
	ID         int       `json:"id"`
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished"`
	Stages     []string  `json:"stages"`
	Categories []string  `json:"categories"`
	Found      int       `json:"found"`
	New        int       `json:"new"`
	Scanned    int       `json:"scanned"`
	Outcome    string    `json:"outcome"`
}

type stateFile struct {
	Repos map[string]*Repo `json:"repos"`
	Runs  []RunRecord      `json:"runs"`
}

type Store struct {
	mu     sync.RWMutex
	saveMu sync.Mutex // serialises writers of the state file (they share one .tmp path)
	path   string
	repos  map[string]*Repo
	runs   []RunRecord
	dirty  chan struct{}
}

func openStore(path string) (*Store, error) {
	s := &Store{path: path, repos: map[string]*Repo{}, dirty: make(chan struct{}, 1)}
	b, err := os.ReadFile(path)
	if err == nil {
		var sf stateFile
		if err := json.Unmarshal(b, &sf); err != nil {
			return nil, err
		}
		if sf.Repos != nil {
			s.repos = sf.Repos
		}
		s.runs = sf.Runs
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	go s.saver()
	return s, nil
}

func (s *Store) saver() {
	for range s.dirty {
		time.Sleep(2 * time.Second) // coalesce bursts
		_ = s.SaveNow()
	}
}

func (s *Store) markDirty() {
	select {
	case s.dirty <- struct{}{}:
	default:
	}
}

func (s *Store) SaveNow() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.RLock()
	b, err := json.Marshal(stateFile{Repos: s.repos, Runs: s.runs})
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, b, 0o644)
}

// With runs fn under the write lock and schedules a save.
func (s *Store) With(fn func(repos map[string]*Repo)) {
	s.mu.Lock()
	fn(s.repos)
	s.mu.Unlock()
	s.markDirty()
}

// Read runs fn under the read lock.
func (s *Store) Read(fn func(repos map[string]*Repo)) {
	s.mu.RLock()
	fn(s.repos)
	s.mu.RUnlock()
}

func (s *Store) Get(key string) (Repo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.repos[key]
	if !ok {
		return Repo{}, false
	}
	return *r, true
}

// GetJSON encodes one repo while holding the read lock. A plain copy from Get still shares
// pointers (Enriched, Scan) that a running pipeline may be mutating.
func (s *Store) GetJSON(key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.repos[key]
	if !ok {
		return nil, false
	}
	b, err := json.Marshal(r)
	return b, err == nil
}

func (s *Store) AddRun(r RunRecord) int {
	s.mu.Lock()
	// not len+1: the list is capped, so that would hand out the same ID forever once it's full
	r.ID = 1
	if n := len(s.runs); n > 0 {
		r.ID = s.runs[n-1].ID + 1
	}
	s.runs = append(s.runs, r)
	if len(s.runs) > 100 {
		s.runs = s.runs[len(s.runs)-100:]
	}
	s.mu.Unlock()
	s.markDirty()
	return r.ID
}

func (s *Store) FinishRun(id int, fn func(r *RunRecord)) {
	s.mu.Lock()
	for i := range s.runs {
		if s.runs[i].ID == id {
			fn(&s.runs[i])
		}
	}
	s.mu.Unlock()
	s.markDirty()
}

func (s *Store) Runs() []RunRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RunRecord, len(s.runs))
	copy(out, s.runs)
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func addUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func hasAny(list []string, set map[string]bool) bool {
	for _, x := range list {
		if set[x] {
			return true
		}
	}
	return false
}
