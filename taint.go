package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Plan 7 + plan 12 layer 2: run Semgrep with sift's own taint rules over the files that have
// checker findings, and mark a finding confirmed when Semgrep flags the same line for the same
// bug class. Two independent analyses agreeing is the strongest signal sift gives without
// running anything. Semgrep only ever reads the extracted files; nothing from a repo is run.

type SemgrepRun struct {
	At      time.Time `json:"at"`
	Ref     string    `json:"ref"`
	Files   int       `json:"files"`
	Results int       `json:"results"`
	Error   string    `json:"error,omitempty"`
}

const (
	semgrepRepoTimeout = 5 * time.Minute
	semgrepConcurrency = 2 // Semgrep itself is multi-threaded and memory-hungry
	maxExtractBytes    = 64 << 20
	maxExtractFiles    = 400
)

// semgrepBin finds Semgrep: the configured path, then PATH, then sift's own venv.
func semgrepBin(s Settings) string {
	if s.SemgrepPath != "" {
		if _, err := os.Stat(s.SemgrepPath); err == nil {
			return s.SemgrepPath
		}
	}
	if p, err := exec.LookPath("semgrep"); err == nil {
		return p
	}
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		p := filepath.Join(la, "sift", "semgrep-venv", "Scripts", "semgrep.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".local", "share", "sift", "semgrep-venv", "bin", "semgrep")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// writeSemgrepRules copies the embedded rules into dir and returns their paths.
func writeSemgrepRules(dir string) ([]string, error) {
	var out []string
	err := fs.WalkDir(defaultsFS, "defaults/semgrep", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isYAML(p) {
			return err
		}
		b, err := defaultsFS.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, path.Base(p))
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return err
		}
		out = append(out, dst)
		return nil
	})
	return out, err
}

// extractFiles writes the named archive entries (paths after the zipball's top folder) into
// dest. It goes through os.Root, which refuses any path that escapes dest, skips everything that
// isn't a regular file, and stops at the file and byte caps, counting real decompressed bytes.
func extractFiles(zipPath, dest string, want map[string]bool, strip bool) (int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	root, err := os.OpenRoot(dest)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	var total int64
	n := 0
	for _, f := range zr.File {
		name := f.Name
		if strip {
			if i := strings.IndexByte(name, '/'); i >= 0 {
				name = name[i+1:]
			}
		}
		if !want[name] || !f.Mode().IsRegular() {
			continue
		}
		clean := path.Clean(name)
		if clean != name || strings.HasPrefix(clean, "../") || path.IsAbs(clean) || strings.Contains(clean, ":") {
			continue
		}
		if n >= maxExtractFiles {
			return n, errors.New("too many files to extract")
		}
		if err := mkdirAllRoot(root, path.Dir(clean)); err != nil {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := root.OpenFile(filepath.FromSlash(clean), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			rc.Close()
			continue
		}
		w, err := io.Copy(out, io.LimitReader(rc, maxExtractBytes-total+1))
		out.Close()
		rc.Close()
		total += w
		if err != nil || total > maxExtractBytes {
			return n, errors.New("extracted files over the size cap")
		}
		n++
	}
	return n, nil
}

func mkdirAllRoot(root *os.Root, dir string) error {
	if dir == "." || dir == "" {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(dir, "/") {
		cur = path.Join(cur, part)
		if err := root.Mkdir(filepath.FromSlash(cur), 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return nil
}

type semgrepResult struct {
	Path  string
	Line  int
	Class string
	Rule  string
}

// runSemgrep runs bin with the rule files over dir and returns its results.
func runSemgrep(ctx context.Context, bin string, rules []string, dir string) ([]semgrepResult, error) {
	ctx, cancel := context.WithTimeout(ctx, semgrepRepoTimeout)
	defer cancel()
	args := []string{"--json", "--quiet", "--metrics=off", "--disable-version-check",
		"--timeout", "30", "--max-target-bytes", "1000000", "--jobs", "2", "--no-git-ignore"}
	for _, r := range rules {
		args = append(args, "--config", r)
	}
	args = append(args, dir)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0", "PYTHONIOENCODING=utf-8")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("semgrep timed out after %s", semgrepRepoTimeout)
	}
	var out struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Metadata struct {
					Class string `json:"class"`
				} `json:"metadata"`
			} `json:"extra"`
		} `json:"results"`
	}
	if jerr := json.Unmarshal(stdout.Bytes(), &out); jerr != nil {
		if err != nil {
			return nil, fmt.Errorf("semgrep: %v: %s", err, firstLine(stderr.Bytes()))
		}
		return nil, fmt.Errorf("semgrep output: %v", jerr)
	}
	var res []semgrepResult
	for _, r := range out.Results {
		p := filepath.ToSlash(r.Path)
		if rel, err := filepath.Rel(dir, r.Path); err == nil {
			p = filepath.ToSlash(rel)
		}
		res = append(res, semgrepResult{Path: p, Line: r.Start.Line, Class: r.Extra.Metadata.Class, Rule: r.CheckID})
	}
	return res, nil
}

// confirmFindings marks findings Semgrep agrees with (same file, same class, within a line).
func confirmFindings(findings []Finding, results []semgrepResult) int {
	n := 0
	for i := range findings {
		f := &findings[i]
		f.Confirmed = false
		for _, r := range results {
			if r.Path == f.Path && r.Class == f.Class && r.Line >= f.Line-1 && r.Line <= f.Line+1 {
				f.Confirmed = true
				n++
				break
			}
		}
	}
	return n
}

// findingsWeight sums finding weights; a Semgrep-confirmed finding counts half again.
func findingsWeight(fs []Finding) float64 {
	w := 0.0
	for _, f := range fs {
		if f.Confirmed {
			w += f.Weight * 1.5
		} else {
			w += f.Weight
		}
	}
	return w
}

// ---------- stage 4: taint ----------

func (a *App) stageTaint(ctx context.Context, h *HTTP, working []string, s Settings) int {
	bin := semgrepBin(s)
	if bin == "" {
		a.logf("semgrep: not installed, skipping confirmation (see docs/plans/07-semgrep.md)")
		return 0
	}
	topN := s.SemgrepTopN
	if topN <= 0 {
		topN = 30
	}
	type target struct {
		key, url, ref string
		files         map[string]bool
		score         float64
	}
	var targets []target
	a.store.Read(func(repos map[string]*Repo) {
		for _, k := range working {
			r := repos[k]
			sc := r.Scan
			if !r.Filter.Pass || sc == nil || sc.Error != "" || len(sc.Findings) == 0 || r.Score == nil {
				continue
			}
			if sc.Semgrep != nil && sc.Semgrep.Ref == sc.Ref && sc.Semgrep.Error == "" && !sc.Semgrep.At.Before(sc.At) {
				continue // already confirmed against this scan
			}
			t := target{key: k, ref: sc.Ref, files: map[string]bool{}, score: r.Score.Total}
			switch {
			case r.Source == "wordpress":
				t.url = r.DownloadURL
			case r.GitHubRepo != "" && sc.Ref != "":
				t.url = "https://api.github.com/repos/" + r.GitHubRepo + "/zipball/" + sc.Ref
			default:
				continue
			}
			for _, f := range sc.Findings {
				t.files[f.Path] = true
			}
			targets = append(targets, t)
		}
	})
	sort.Slice(targets, func(i, j int) bool { return targets[i].score > targets[j].score })
	if len(targets) > topN {
		targets = targets[:topN]
	}
	if len(targets) == 0 {
		a.logf("semgrep: nothing new to confirm")
		return 0
	}
	rulesDir, err := os.MkdirTemp(a.tmpDir, "rules-")
	if err == nil {
		defer os.RemoveAll(rulesDir)
	} else if err = os.MkdirAll(a.tmpDir, 0o700); err == nil {
		rulesDir, err = os.MkdirTemp(a.tmpDir, "rules-")
		defer os.RemoveAll(rulesDir)
	}
	if err != nil {
		a.warnf("semgrep: %v", err)
		return 0
	}
	rules, err := writeSemgrepRules(rulesDir)
	if err != nil || len(rules) == 0 {
		a.warnf("semgrep: no rules (%v)", err)
		return 0
	}
	a.logf("semgrep: confirming findings in the top %d repos", len(targets))
	a.setProgress("semgrep", 0, len(targets))
	var mu sync.Mutex
	done, confirmed := 0, 0
	sem := make(chan struct{}, semgrepConcurrency)
	var wg sync.WaitGroup
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			run, results := a.semgrepOne(ctx, h, bin, rules, t.url, t.ref, t.files, s)
			if ctx.Err() != nil {
				return
			}
			n := 0
			a.store.With(func(repos map[string]*Repo) {
				sc := repos[t.key].Scan
				if sc == nil || sc.Ref != t.ref {
					return // rescanned meanwhile
				}
				if run.Error == "" {
					n = confirmFindings(sc.Findings, results)
					sc.FindingsWeight = findingsWeight(sc.Findings)
				}
				sc.Semgrep = run
			})
			if run.Error != "" {
				a.warnf("semgrep %s: %s", strings.TrimPrefix(t.key, "gh:"), run.Error)
			} else if n > 0 {
				a.logf("semgrep %s: confirmed %d finding(s)", strings.TrimPrefix(t.key, "gh:"), n)
			}
			mu.Lock()
			done++
			confirmed += n
			d := done
			mu.Unlock()
			a.setProgress("semgrep", d, len(targets))
		}()
	}
	wg.Wait()
	a.logf("semgrep: %d finding(s) confirmed", confirmed)
	return confirmed
}

func (a *App) semgrepOne(ctx context.Context, h *HTTP, bin string, rules []string, url, ref string, files map[string]bool, s Settings) (*SemgrepRun, []semgrepResult) {
	run := &SemgrepRun{At: time.Now(), Ref: ref}
	zipPath, _, err := h.DownloadToTemp(ctx, url, a.tmpDir, int64(s.MaxRepoSizeMB)<<20)
	if err != nil {
		run.Error = err.Error()
		return run, nil
	}
	defer os.Remove(zipPath)
	dir, err := os.MkdirTemp(a.tmpDir, "src-")
	if err != nil {
		run.Error = err.Error()
		return run, nil
	}
	defer os.RemoveAll(dir)
	n, err := extractFiles(zipPath, dir, files, true)
	run.Files = n
	if err != nil {
		run.Error = err.Error()
		return run, nil
	}
	if n == 0 {
		run.Error = "none of the finding files were in the archive"
		return run, nil
	}
	results, err := runSemgrep(ctx, bin, rules, dir)
	if err != nil {
		run.Error = err.Error()
		return run, nil
	}
	run.Results = len(results)
	return run, results
}
