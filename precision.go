package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// The precision bench (plan 18): the bench asks whether sift catches known bugs, this asks
// whether it still fires on lines a human read and called safe. Labels are in the repo; the
// files they point at are third-party code, so they stay snapshots in data/bench/precision.

type PrecisionLabel struct {
	Repo    string `json:"repo"` // owner/name, or wp:slug
	Path    string `json:"path"`
	Checker string `json:"checker"`
	Match   string `json:"match"` // text of the line, so a refreshed snapshot keeps its label
	Label   string `json:"label"` // real | false
	Why     string `json:"why"`
}

type PrecisionResult struct {
	PrecisionLabel
	Status string `json:"status"` // fired | quiet | stale (line gone) | missing (no snapshot)
}

type PrecisionReport struct {
	FalseAlarms int               `json:"false_alarms"` // labelled false, scored
	Silenced    int               `json:"silenced"`     // of those, quiet now
	Real        int               `json:"real"`         // labelled real, scored
	Kept        int               `json:"kept"`         // of those, still flagged
	Unscored    int               `json:"unscored"`     // stale or missing
	Results     []PrecisionResult `json:"results"`
}

func loadPrecisionLabels() ([]PrecisionLabel, error) {
	b, err := defaultsFS.ReadFile("defaults/precision.json")
	if err != nil {
		return nil, err
	}
	var out []PrecisionLabel
	return out, json.Unmarshal(b, &out)
}

func (a *App) precisionFile(l PrecisionLabel) string {
	sum := sha1.Sum([]byte(l.Repo + "\x00" + l.Path))
	return filepath.Join(a.benchDir(), "precision", hex.EncodeToString(sum[:8])+".txt.gz")
}

// PrecisionCollect fetches the snapshots it doesn't have yet.
func (a *App) PrecisionCollect(ctx context.Context) (int, error) {
	labels, err := loadPrecisionLabels()
	if err != nil {
		return 0, err
	}
	token, _ := a.settings.Get().TokenAndSource()
	h := newHTTP(token, a.logf)
	added := 0
	for _, l := range labels {
		p := a.precisionFile(l)
		if _, err := os.Stat(p); err == nil {
			continue
		}
		src, err := h.precisionSource(ctx, l)
		if err != nil {
			a.warnf("[bench] precision %s %s: %v", l.Repo, l.Path, err)
			continue
		}
		if err := writeGzip(p, src); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}

func (h *HTTP) precisionSource(ctx context.Context, l PrecisionLabel) (string, error) {
	if slug, ok := strings.CutPrefix(l.Repo, "wp:"); ok {
		segs := strings.Split(l.Path, "/")
		for i, s := range segs {
			segs[i] = url.PathEscape(s)
		}
		resp, err := h.Do(ctx, "GET", "https://plugins.svn.wordpress.org/"+url.PathEscape(slug)+"/trunk/"+strings.Join(segs, "/"), nil, "")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("%d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, benchMaxFileSize*4))
		return string(b), err
	}
	owner, repo, ok := strings.Cut(l.Repo, "/")
	if !ok {
		return "", errors.New("repo is not owner/name")
	}
	return h.rawFile(ctx, owner, repo, "HEAD", l.Path)
}

func writeGzip(p, s string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write([]byte(s)); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}
	return os.WriteFile(p, b.Bytes(), 0o644)
}

func readGzip(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	return io.ReadAll(z)
}

// precisionStatus runs the checkers over one file, read as an app rather than a library.
func precisionStatus(l PrecisionLabel, src []byte, checkers []*Checker) string {
	var at []int
	for i, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, l.Match) {
			at = append(at, i+1)
		}
	}
	if len(at) == 0 {
		return "stale"
	}
	for _, f := range checkFileLib(l.Path, src, checkers, false) {
		if f.Checker != l.Checker {
			continue
		}
		for _, n := range at {
			if f.Line >= n-2 && f.Line <= n+2 {
				return "fired"
			}
		}
	}
	return "quiet"
}

func (a *App) scorePrecision(checkers []*Checker) *PrecisionReport {
	labels, err := loadPrecisionLabels()
	if err != nil {
		a.warnf("[bench] precision labels: %v", err)
		return nil
	}
	rep := &PrecisionReport{}
	for _, l := range labels {
		res := PrecisionResult{PrecisionLabel: l, Status: "missing"}
		if src, err := readGzip(a.precisionFile(l)); err == nil {
			res.Status = precisionStatus(l, src, checkers)
		}
		switch {
		case res.Status == "stale" || res.Status == "missing":
			rep.Unscored++
		case l.Label == "real":
			rep.Real++
			if res.Status == "fired" {
				rep.Kept++
			}
		default:
			rep.FalseAlarms++
			if res.Status == "quiet" {
				rep.Silenced++
			}
		}
		rep.Results = append(rep.Results, res)
	}
	return rep
}

func formatPrecision(p *PrecisionReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nprecision: %d of %d false alarms silenced, %d of %d real bugs kept, %d unscored\n", p.Silenced, p.FalseAlarms, p.Kept, p.Real, p.Unscored)
	for _, r := range p.Results {
		if r.Label == "real" && r.Status == "fired" || r.Label != "real" && r.Status == "quiet" {
			continue
		}
		fmt.Fprintf(&b, "  %-7s %-5s %-18s %s %s\n", r.Status, r.Label, r.Checker, r.Repo, r.Path)
	}
	return b.String()
}
