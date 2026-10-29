package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

var skipDirs = []string{
	"node_modules/", "vendor/", "dist/", "build/", ".git/", "third_party/", "third-party/", "thirdparty/",
	"bower_components/", "target/", "out/", "coverage/", "__pycache__/", ".venv/", "venv/", "site-packages/",
	".next/", ".nuxt/", "public/build/", "static/vendor/", "assets/vendor/", "lib/vendor/", "external/", "deps/",
	"examples/", "example/", "docs/", "doc/", "benchmarks/", "bench/", "fixtures/", "testdata/", "samples/",
}

// Test detection is split by where the marker may appear, so "latest_release.py" or
// "contest.go" aren't mistaken for tests.
var (
	testDirs     = []string{"/test/", "/tests/", "/__tests__/", "/spec/", "/specs/", "/e2e/", "/src/test/", "/testing/", "/__mocks__/"}
	testPrefixes = []string{"test_"}
	testSuffixes = []string{"_test.go", "_spec.rb", "_test.py", "tests.py"}
	testInfixes  = []string{".test.", ".spec."}
	testExact    = map[string]bool{"conftest.py": true, "setuptests.js": true, "setuptests.ts": true}
	// JUnit naming (FooTest.java, FooTests.kt, FooIT.java) — matched on original case so
	// "Latest.java" or "Contest.kt" don't count.
	jvmTestRe = regexp.MustCompile(`^[A-Z][A-Za-z0-9_]*(?:Test|Tests|IT)\.(?:java|kt)$`)
)

// isTestPath takes the lowercased path plus the original-case base name.
func isTestPath(lp, origBase string) bool {
	for _, d := range testDirs {
		if strings.Contains(lp, d) {
			return true
		}
	}
	if jvmTestRe.MatchString(origBase) {
		return true
	}
	base := path.Base(lp)
	if testExact[base] {
		return true
	}
	for _, p := range testPrefixes {
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	for _, s := range testSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	for _, x := range testInfixes {
		if strings.Contains(base, x) {
			return true
		}
	}
	return false
}

type scanOpts struct {
	Profiles    []*SinkProfile
	SkipTests   bool
	MaxFileSize int64
	StripPrefix bool // drop the first path component (zipball / plugin folder)
	Checkers    []*Checker
}

// scanEngine goes up whenever the scanner, sink profiles or checkers change what a scan finds,
// so the next run rescans repos whose stored scan is older even if their code hasn't moved.
const scanEngine = 2

const (
	maxSinkHitsKept    = 250
	maxSurfaceHitsKept = 60
	maxAuthHitsKept    = 40
)

func isMinified(b []byte) bool {
	if len(b) < 2000 {
		return false
	}
	lines := bytes.Count(b, []byte{'\n'}) + 1
	return len(b)/lines > 400
}

func shouldSkip(p string, skipTests bool, extra []string) bool {
	lp := "/" + strings.ToLower(p)
	for _, d := range skipDirs {
		if strings.Contains(lp, "/"+d) {
			return true
		}
	}
	if strings.HasSuffix(lp, ".min.js") || strings.HasSuffix(lp, ".bundle.js") || strings.HasSuffix(lp, ".map") || strings.HasSuffix(lp, ".d.ts") {
		return true
	}
	if skipTests && isTestPath(lp, path.Base(p)) {
		return true
	}
	for _, x := range extra {
		if x != "" && strings.Contains(lp, strings.ToLower(x)) {
			return true
		}
	}
	return false
}

// safeScanZip turns a panic while scanning one (untrusted) archive into that repo's scan
// error, so a bug triggered by one strange file can't take the whole server down.
func safeScanZip(zipPath string, opts scanOpts) (res *ScanResult, err error) {
	defer func() {
		if p := recover(); p != nil {
			res, err = nil, fmt.Errorf("scanner crashed on this repo: %v", p)
		}
	}()
	return scanZip(zipPath, opts)
}

// scanZip greps every source file in a zip archive with the matching sink profiles.
func scanZip(zipPath string, opts scanOpts) (*ScanResult, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	byExt := map[string][]*SinkProfile{}
	for _, p := range opts.Profiles {
		for _, x := range p.Extensions {
			byExt[x] = append(byExt[x], p)
		}
	}
	res := &ScanResult{At: time.Now(), ByClass: map[string]int{}, Engine: scanEngine}
	var sinks, surface, auth []Hit
	var findings []Finding

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := f.Name
		if opts.StripPrefix {
			if i := strings.IndexByte(name, '/'); i >= 0 {
				name = name[i+1:]
			}
		}
		profs := byExt[strings.ToLower(path.Ext(name))]
		if len(profs) == 0 {
			continue
		}
		var extraSkip []string
		for _, p := range profs {
			extraSkip = append(extraSkip, p.SkipPaths...)
		}
		if shouldSkip(name, opts.SkipTests, extraSkip) {
			continue
		}
		if int64(f.UncompressedSize64) > opts.MaxFileSize {
			res.Truncated = true
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, opts.MaxFileSize+1))
		rc.Close()
		if err != nil || isMinified(b) || bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0 {
			continue
		}
		res.Files++
		res.Bytes += int64(len(b))

		if len(opts.Checkers) > 0 && len(findings) < maxFindingsPerRepo {
			findings = append(findings, runCheckers(name, b, opts.Checkers)...)
		}
		fb := fileBytes{b: b, lower: asciiLower(b), starts: lineStartsBytes(b)}
		for _, p := range profs {
			scanFile(name, fb, p.Surface, "surface", &surface, &res.SurfaceHits, nil, nil)
			scanFile(name, fb, p.Sinks, "sink", &sinks, &res.SinkHits, &res.WeightedSinks, res.ByClass)
			scanFile(name, fb, p.Auth, "auth", &auth, &res.AuthHits, nil, nil)
		}
	}

	res.PairedFiles, res.PairedWeight, res.HotFiles = pairHits(append(sinks, surface...))
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Weight > findings[j].Weight })
	if len(findings) > maxFindingsPerRepo {
		findings = findings[:maxFindingsPerRepo]
	}
	res.FindingsWeight = findingsWeight(findings)
	res.Findings = findings
	sort.SliceStable(sinks, func(i, j int) bool { return sinks[i].Weight > sinks[j].Weight })
	if len(sinks) > maxSinkHitsKept {
		sinks = sinks[:maxSinkHitsKept]
		res.Truncated = true
	}
	if len(surface) > maxSurfaceHitsKept {
		surface = surface[:maxSurfaceHitsKept]
	}
	if len(auth) > maxAuthHitsKept {
		auth = auth[:maxAuthHitsKept]
	}
	res.Hits = append(append(sinks, surface...), auth...)
	return res, nil
}

type fileBytes struct {
	b, lower []byte
	starts   []int
}

// line returns line i without its line ending, so patterns ending in $ behave as per-line.
func (f fileBytes) line(i int) []byte {
	end := len(f.b)
	if i+1 < len(f.starts) {
		end = f.starts[i+1]
	}
	l := f.b[f.starts[i]:end]
	for len(l) > 0 && (l[len(l)-1] == 0x0a || l[len(l)-1] == 0x0d) {
		l = l[:len(l)-1]
	}
	return l
}

// matchLines returns the lines pt matches, one line at a time. Patterns with required literals
// only run on lines containing one of them (see litfilter.go); the few without run on every line.
func (pt Pattern) matchLines(f fileBytes) []int {
	var out []int
	if pt.lits != nil {
		for _, i := range litLines(f.lower, f.starts, pt.lits) {
			if pt.re.Match(f.line(i)) {
				out = append(out, i)
			}
		}
		return out
	}
	if !pt.re.Match(f.b) {
		return nil
	}
	for i := range f.starts {
		if pt.re.Match(f.line(i)) {
			out = append(out, i)
		}
	}
	return out
}

func scanFile(name string, f fileBytes, pats []Pattern, kind string, hits *[]Hit, count *int, weighted *float64, byClass map[string]int) {
	for _, pt := range pats {
		if pt.re == nil {
			continue
		}
		perFile := 0
		for _, line := range pt.matchLines(f) {
			perFile++
			*count++
			if weighted != nil {
				// diminishing returns: the 10th identical hit in one file says less than the first
				if perFile <= 5 {
					*weighted += pt.Weight
				} else {
					*weighted += pt.Weight * 0.2
				}
			}
			if byClass != nil && pt.Class != "" {
				byClass[pt.Class]++
			}
			if perFile <= 8 {
				snip := strings.TrimSpace(string(f.line(line)))
				if len(snip) > 220 {
					snip = snip[:220] + "…"
				}
				*hits = append(*hits, Hit{Path: name, Line: line + 1, Kind: kind, Label: pt.Label, Class: pt.Class, Weight: pt.Weight, Snippet: snip})
			}
		}
	}
}

const (
	nearLines    = 40 // a sink this close to a surface is probably in the same handler
	maxHotFiles  = 15
	nearBonus    = 1.5
	hotRepeatCap = 5 // same pattern more than this many times in one file counts at 0.2, as in scanFile
)

// pairHits finds files where input enters and something dangerous happens: at least one
// surface hit and one sink hit in the same file. That's the shape of a real bug, unlike
// fifty sinks in one file and fifty routes in another.
func pairHits(hits []Hit) (int, float64, []HotFile) {
	type fileHits struct{ surface, sinks []Hit }
	byPath := map[string]*fileHits{}
	for _, h := range hits {
		fh := byPath[h.Path]
		if fh == nil {
			fh = &fileHits{}
			byPath[h.Path] = fh
		}
		switch h.Kind {
		case "surface":
			fh.surface = append(fh.surface, h)
		case "sink":
			fh.sinks = append(fh.sinks, h)
		}
	}
	var hot []HotFile
	total := 0.0
	for p, fh := range byPath {
		if len(fh.surface) == 0 || len(fh.sinks) == 0 {
			continue
		}
		hf := HotFile{Path: p}
		seen := map[string]int{}
		classes := map[string]bool{}
		for _, s := range fh.sinks {
			w := s.Weight
			if seen[s.Label]++; seen[s.Label] > hotRepeatCap {
				w *= 0.2
			}
			for _, su := range fh.surface {
				if d := s.Line - su.Line; d >= -nearLines && d <= nearLines {
					w *= nearBonus
					hf.Near = true
					break
				}
			}
			hf.Weight += w
			if s.Class != "" {
				classes[s.Class] = true
			}
		}
		for c := range classes {
			hf.Classes = append(hf.Classes, c)
		}
		sort.Strings(hf.Classes)
		hf.Weight = math.Round(hf.Weight*10) / 10
		total += hf.Weight
		hot = append(hot, hf)
	}
	sort.Slice(hot, func(i, j int) bool {
		if hot[i].Weight != hot[j].Weight {
			return hot[i].Weight > hot[j].Weight
		}
		return hot[i].Path < hot[j].Path
	})
	n := len(hot)
	if len(hot) > maxHotFiles {
		hot = hot[:maxHotFiles]
	}
	return n, math.Round(total*10) / 10, hot
}

// profilesFor returns the sink profiles a category asked for (all when it names none).
func profilesFor(c *Category, all []*SinkProfile) []*SinkProfile {
	if len(c.Sinks) == 0 {
		return all
	}
	want := map[string]bool{}
	for _, s := range c.Sinks {
		want[slugID(s)] = true
	}
	var out []*SinkProfile
	for _, p := range all {
		if want[p.ID] {
			out = append(out, p)
		}
	}
	return out
}

func lineStartsBytes(b []byte) []int {
	st := []int{0}
	for i, c := range b {
		if c == 0x0a {
			st = append(st, i+1)
		}
	}
	return st
}
