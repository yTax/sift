package main

import (
	"archive/zip"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Extraction is the one place sift writes downloaded code to disk, so it must not be
// zip-slippable: no entry may land outside dest, and links are never created.
func TestExtractFilesRejectsEscapes(t *testing.T) {
	tmp := t.TempDir()
	zp := filepath.Join(tmp, "evil.zip")
	f, _ := os.Create(zp)
	zw := zip.NewWriter(f)
	add := func(name, body string, mode fs.FileMode) {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if mode != 0 {
			h.SetMode(mode)
		}
		w, _ := zw.CreateHeader(h)
		w.Write([]byte(body))
	}
	add("top/ok/app.py", "print(1)\n", 0)
	add("top/../../escaped.py", "x", 0)
	add("top/ok/../../escaped2.py", "x", 0)
	add("top//abs.py", "x", 0)
	add("top/C:/win.py", "x", 0)
	add("top/link.py", "/etc/passwd", fs.ModeSymlink|0o777)
	zw.Close()
	f.Close()

	dest := filepath.Join(tmp, "dest")
	os.Mkdir(dest, 0o700)
	want := map[string]bool{"ok/app.py": true, "../../escaped.py": true, "ok/../../escaped2.py": true, "/abs.py": true, "C:/win.py": true, "link.py": true}
	n, err := extractFiles(zp, dest, want, true)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("extracted %d files, want only ok/app.py", n)
	}
	if _, err := os.Stat(filepath.Join(dest, "ok", "app.py")); err != nil {
		t.Errorf("ok/app.py missing: %v", err)
	}
	filepath.WalkDir(tmp, func(p string, d fs.DirEntry, err error) error {
		if d != nil && !d.IsDir() && !strings.HasPrefix(p, dest) && p != zp {
			t.Errorf("file written outside dest: %s", p)
		}
		if d != nil && d.Type()&fs.ModeSymlink != 0 {
			t.Errorf("symlink created: %s", p)
		}
		return nil
	})
}

func TestConfirmFindings(t *testing.T) {
	fs := []Finding{
		{Path: "a.py", Line: 10, Class: "cmd-exec", Weight: 4},
		{Path: "a.py", Line: 20, Class: "sqli", Weight: 4},
		{Path: "b.py", Line: 5, Class: "ssrf", Weight: 2},
	}
	n := confirmFindings(fs, []semgrepResult{
		{Path: "a.py", Line: 11, Class: "cmd-exec"}, // one line off: same call wrapped
		{Path: "a.py", Line: 20, Class: "xss"},      // same line, different bug class
		{Path: "c.py", Line: 5, Class: "ssrf"},      // different file
	})
	if n != 1 || !fs[0].Confirmed || fs[1].Confirmed || fs[2].Confirmed {
		t.Errorf("confirmed %d: %+v", n, fs)
	}
	if w := findingsWeight(fs); w != 4*1.5+4+2 {
		t.Errorf("weight %v", w)
	}
}

// End to end against the real Semgrep, when it's installed: the checker's findings on known
// vulnerable snippets get confirmed by sift's Semgrep rules.
func TestSemgrepConfirmsCheckerFindings(t *testing.T) {
	bin := semgrepBin(Settings{})
	if bin == "" || testing.Short() {
		t.Skip("semgrep not installed")
	}
	checkers, _ := loadCheckers("")
	dir := t.TempDir()
	type want struct{ file, checker string }
	var cases []want
	var all []Finding
	for i, c := range checkerCases {
		if !c.want || c.checker == "prefix-containment" || c.checker == wpAuthzChecker {
			continue // no Semgrep equivalent for these
		}
		name := filepath.Base(c.file)
		name = strings.TrimSuffix(name, filepath.Ext(name)) + "_" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + filepath.Ext(name)
		os.WriteFile(filepath.Join(dir, name), []byte(c.src), 0o600)
		for _, f := range runCheckers(name, []byte(c.src), checkers) {
			if f.Checker == c.checker {
				all = append(all, f)
			}
		}
		cases = append(cases, want{name, c.checker})
	}
	rulesDir := t.TempDir()
	rules, err := writeSemgrepRules(rulesDir)
	if err != nil || len(rules) == 0 {
		t.Fatalf("rules: %v", err)
	}
	results, err := runSemgrep(context.Background(), bin, rules, dir)
	if err != nil {
		t.Fatal(err)
	}
	n := confirmFindings(all, results)
	confirmedFiles := map[string]bool{}
	for _, f := range all {
		if f.Confirmed {
			confirmedFiles[f.Path] = true
		}
	}
	t.Logf("%d of %d vulnerable snippets confirmed (%d findings)", len(confirmedFiles), len(cases), n)
	if len(confirmedFiles)*10 < len(cases)*7 {
		t.Errorf("only %d of %d confirmed; missing:", len(confirmedFiles), len(cases))
		for _, c := range cases {
			if !confirmedFiles[c.file] {
				t.Logf("  %s (%s)", c.file, c.checker)
			}
		}
	}
}
