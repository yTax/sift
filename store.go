package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	_ "modernc.org/sqlite"
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
	// Already found: the repo's published advisories, and open issues that read like security
	// reports nobody has fixed yet. Information for you, not a filter.
	KnownAdvisories []KnownAdvisory `json:"known_advisories,omitempty"`
	SecurityIssues  []IssueRef      `json:"security_issues,omitempty"`
	RecentCommits   int             `json:"recent_commits"`
	Topics          []string        `json:"topics,omitempty"`
	Homepage        string          `json:"homepage,omitempty"`
	License         string          `json:"license,omitempty"`
	Error           string          `json:"error,omitempty"`
}

type KnownAdvisory struct {
	ID        string     `json:"id"` // GHSA id
	CVE       string     `json:"cve,omitempty"`
	Summary   string     `json:"summary"`
	Severity  string     `json:"severity,omitempty"`
	CWEs      []string   `json:"cwes,omitempty"`
	URL       string     `json:"url,omitempty"`
	Published *time.Time `json:"published,omitempty"`
}

type IssueRef struct {
	Title     string    `json:"title"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
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
	Engine        int            `json:"engine"` // scanEngine that produced this; older ones get rescanned
	// Pairing: files where input enters (surface) and a sink sits in the same file.
	PairedFiles  int       `json:"paired_files"`
	PairedWeight float64   `json:"paired_weight"`
	HotFiles     []HotFile `json:"hot_files,omitempty"` // best first: where to start reading
	// Checker results (plan 12): specific lines that look like a known bug class.
	Findings       []Finding   `json:"findings,omitempty"`
	FindingsWeight float64     `json:"findings_weight"`
	Semgrep        *SemgrepRun `json:"semgrep,omitempty"` // last confirmation pass over this scan's findings
}

type HotFile struct {
	Path    string   `json:"path"`
	Weight  float64  `json:"weight"` // sink weight in the file, x1.5 for sinks near a surface
	Near    bool     `json:"near"`   // a sink within nearLines of a surface
	Classes []string `json:"classes,omitempty"`
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

	// Your call after reading the code: was the lead worth it? Score parts are kept as they were
	// when you decided, so the ranking can later learn which parts actually predicted good leads.
	Verdict      string             `json:"verdict,omitempty"` // real | dud
	VerdictAt    *time.Time         `json:"verdict_at,omitempty"`
	VerdictParts map[string]float64 `json:"verdict_parts,omitempty"`
}

var validStatus = map[string]bool{"new": true, "shortlist": true, "digging": true, "reported": true, "skipped": true}

var validVerdict = map[string]bool{"": true, "real": true, "dud": true}

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

// stateFile is the old data/state.json format, read once by importStateFile and never written.
type stateFile struct {
	Repos map[string]*Repo `json:"repos"`
	Runs  []RunRecord      `json:"runs"`
}

// Store keeps every repo in memory (the pipeline and the API work on the map) and persists it to
// SQLite. A save marshals each repo, compares it with what was last written and writes only the
// rows that changed, so a scan touching one repo writes one row instead of the whole dataset.
type Store struct {
	mu        sync.RWMutex
	saveMu    sync.Mutex // serialises saves; guards saved and savedRuns
	db        *sql.DB
	repos     map[string]*Repo
	runs      []RunRecord
	saved     map[string]uint64 // repo key -> hash of the JSON in the database
	savedRuns map[int]uint64
	dirty     chan struct{}
}

// migrations are applied in order; meta.schema_version counts how many already ran.
// Append only: never edit one that has shipped.
var migrations = []string{
	`CREATE TABLE repos (
		key        TEXT PRIMARY KEY,
		source     TEXT NOT NULL,
		status     TEXT NOT NULL DEFAULT 'new',
		score      REAL,
		passing    INTEGER NOT NULL DEFAULT 0,
		updated_at TEXT NOT NULL,
		json       TEXT NOT NULL
	);
	CREATE INDEX repos_score ON repos(passing, score DESC);
	CREATE INDEX repos_status ON repos(status);
	CREATE TABLE runs (
		id      INTEGER PRIMARY KEY,
		started TEXT NOT NULL,
		json    TEXT NOT NULL
	);`,
}

// openStore opens (or creates) dir/sift.db. On first start it imports dir/state.json, the old
// format, and renames it to state.json.imported so it's kept as a backup but never read again.
func openStore(dir string) (*Store, error) {
	dsn := filepath.Join(dir, "sift.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, repos: map[string]*Repo{}, saved: map[string]uint64{}, savedRuns: map[int]uint64{}, dirty: make(chan struct{}, 1)}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.load(); err != nil {
		db.Close()
		return nil, err
	}
	if len(s.repos) == 0 && len(s.runs) == 0 {
		if err := s.importStateFile(filepath.Join(dir, "state.json")); err != nil {
			db.Close()
			return nil, fmt.Errorf("importing state.json: %w", err)
		}
	}
	go s.saver()
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`); err != nil {
		return err
	}
	var v int
	err := s.db.QueryRow(`SELECT CAST(v AS INTEGER) FROM meta WHERE k = 'schema_version'`).Scan(&v)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("sift.db has schema version %d, this build only knows %d: it was written by a newer sift", v, len(migrations))
	}
	for ; v < len(migrations); v++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO meta (k, v) VALUES ('schema_version', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, v+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) load() error {
	rows, err := s.db.Query(`SELECT key, json FROM repos`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var b []byte
		if err := rows.Scan(&key, &b); err != nil {
			return err
		}
		r := &Repo{}
		if err := json.Unmarshal(b, r); err != nil {
			return fmt.Errorf("repo %s: %w", key, err)
		}
		s.repos[key] = r
		s.saved[key] = hashBytes(b)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = s.db.Query(`SELECT json FROM runs ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return err
		}
		var r RunRecord
		if err := json.Unmarshal(b, &r); err != nil {
			return err
		}
		s.runs = append(s.runs, r)
		s.savedRuns[r.ID] = hashBytes(b)
	}
	return rows.Err()
}

func (s *Store) importStateFile(path string) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var sf stateFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return err
	}
	if sf.Repos != nil {
		s.repos = sf.Repos
	}
	s.runs = sf.Runs
	if err := s.SaveNow(); err != nil {
		return err
	}
	log.Printf("imported %d repos and %d runs from %s into sift.db", len(s.repos), len(s.runs), filepath.Base(path))
	return os.Rename(path, path+".imported")
}

// Close writes anything unsaved and closes the database.
func (s *Store) Close() error {
	err := s.SaveNow()
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if cerr := s.db.Close(); err == nil {
		err = cerr
	}
	return err
}

// saveEvery spaces out background saves. A save only writes changed rows, but it still marshals
// every repo to find them, so it isn't free. Runs call SaveNow when they finish.
const saveEvery = 10 * time.Second

func (s *Store) saver() {
	var last time.Time
	for range s.dirty {
		if wait := saveEvery - time.Since(last); wait > 0 {
			time.Sleep(wait)
		}
		_ = s.SaveNow()
		last = time.Now()
	}
}

func (s *Store) markDirty() {
	select {
	case s.dirty <- struct{}{}:
	default:
	}
}

type repoRow struct {
	key, source, status, updated string
	score                        sql.NullFloat64
	passing                      bool
	json                         []byte
	hash                         uint64
}

type runRow struct {
	id      int
	started string
	json    []byte
	hash    uint64
}

// SaveNow writes every repo and run that changed since the last save, in one transaction.
func (s *Store) SaveNow() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	var repos []repoRow
	var runs []runRow
	seen := make(map[string]bool, len(s.saved))
	seenRuns := make(map[int]bool, len(s.savedRuns))
	s.mu.RLock()
	for key, r := range s.repos {
		seen[key] = true
		b, err := json.Marshal(r)
		if err != nil {
			s.mu.RUnlock()
			return fmt.Errorf("repo %s: %w", key, err)
		}
		h := hashBytes(b)
		if old, ok := s.saved[key]; ok && old == h {
			continue
		}
		row := repoRow{key: key, source: r.Source, status: r.Status, updated: r.UpdatedAt.UTC().Format(time.RFC3339Nano), passing: r.Filter.Pass, json: b, hash: h}
		if r.Score != nil {
			row.score = sql.NullFloat64{Float64: r.Score.Total, Valid: true}
		}
		repos = append(repos, row)
	}
	for _, r := range s.runs {
		seenRuns[r.ID] = true
		b, err := json.Marshal(r)
		if err != nil {
			s.mu.RUnlock()
			return err
		}
		h := hashBytes(b)
		if old, ok := s.savedRuns[r.ID]; ok && old == h {
			continue
		}
		runs = append(runs, runRow{id: r.ID, started: r.Started.UTC().Format(time.RFC3339Nano), json: b, hash: h})
	}
	s.mu.RUnlock()

	var gone []string
	for key := range s.saved {
		if !seen[key] {
			gone = append(gone, key)
		}
	}
	var goneRuns []int
	for id := range s.savedRuns {
		if !seenRuns[id] {
			goneRuns = append(goneRuns, id)
		}
	}
	if len(repos)+len(runs)+len(gone)+len(goneRuns) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(repos) > 0 {
		st, err := tx.Prepare(`INSERT INTO repos (key, source, status, score, passing, updated_at, json) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET source = excluded.source, status = excluded.status, score = excluded.score,
			passing = excluded.passing, updated_at = excluded.updated_at, json = excluded.json`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, r := range repos {
			if _, err := st.Exec(r.key, r.source, r.status, r.score, r.passing, r.updated, r.json); err != nil {
				return fmt.Errorf("repo %s: %w", r.key, err)
			}
		}
	}
	for _, key := range gone {
		if _, err := tx.Exec(`DELETE FROM repos WHERE key = ?`, key); err != nil {
			return err
		}
	}
	for _, r := range runs {
		if _, err := tx.Exec(`INSERT INTO runs (id, started, json) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET started = excluded.started, json = excluded.json`, r.id, r.started, r.json); err != nil {
			return err
		}
	}
	for _, id := range goneRuns {
		if _, err := tx.Exec(`DELETE FROM runs WHERE id = ?`, id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// only now: a failed transaction leaves the old hashes, so the next save retries the same rows
	for _, r := range repos {
		s.saved[r.key] = r.hash
	}
	for _, key := range gone {
		delete(s.saved, key)
	}
	for _, r := range runs {
		s.savedRuns[r.id] = r.hash
	}
	for _, id := range goneRuns {
		delete(s.savedRuns, id)
	}
	return nil
}

func hashBytes(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
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

// Meta reads a value kept beside the repos (the variant feed's state, say); "" when unset.
func (s *Store) Meta(k string) string {
	var v string
	_ = s.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, k).Scan(&v)
	return v
}

func (s *Store) SetMeta(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
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
