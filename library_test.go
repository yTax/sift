package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testApp(t *testing.T) *App {
	t.Helper()
	a, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.store.Close() })
	return a
}

func libPost(t *testing.T, a *App, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, strings.NewReader(string(b)))
	req.Header.Set("X-Sift", "1")
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	a.Routes(os.DirFS(t.TempDir())).ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestLibFileName(t *testing.T) {
	for in, want := range map[string]string{
		"my-dork":          "my-dork.yaml",
		"My Dork.yaml":     "my-dork.yaml",
		"old.yml":          "old.yml",
		"../../etc/passwd": "etc-passwd.yaml",
		`..\..\x`:          "x.yaml",
		"_template":        "template.yaml",
	} {
		if got, err := libFileName("dorks", in); err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "..", "/", "___"} {
		if got, err := libFileName("dorks", bad); err == nil {
			t.Errorf("%q: accepted as %q", bad, got)
		}
	}
	if _, err := libFileName("../data", "x"); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestOverlayAndPrune(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "dorks")
	os.MkdirAll(dir, 0o755)
	bundled, _ := defaultsFS.ReadFile("defaults/dorks/mcp.yaml")
	// an old-style copy (CRLF, as git on Windows writes it), an edit and a new file
	os.WriteFile(filepath.Join(dir, "mcp.yaml"), []byte(strings.ReplaceAll(string(normalizeEOL(bundled)), "\n", "\r\n")), 0o644)
	os.WriteFile(filepath.Join(dir, "wordpress.yaml"), []byte("name: mine\nqueries: [{q: x}]\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "extra.yaml"), []byte("name: extra\nqueries: [{q: y}]\n"), 0o644)
	if n := pruneDefaultCopies(base); n != 1 {
		t.Fatalf("pruned %d, want 1 (the copy)", n)
	}
	origin := map[string]string{}
	for _, f := range overlay(dir, "dorks") {
		origin[f.Name] = f.Origin
	}
	if origin["mcp.yaml"] != "built-in" || origin["wordpress.yaml"] != "edited" || origin["extra.yaml"] != "yours" {
		t.Errorf("origins = %v", origin)
	}
	if _, ok := origin["_template.yaml"]; ok {
		t.Error("templates must not load")
	}
}

func TestLibrarySaveTestRemove(t *testing.T) {
	a := testApp(t)
	checker := `id: my-eval
class: code-exec
weight: 2
message: input reaches eval
langs:
  python:
    sinks: ['\beval\(']
`
	code, out := libPost(t, a, "/api/library/test", map[string]any{"kind": "checkers", "text": checker, "file": "tools/calc.py",
		"code": "@mcp.tool()\ndef calc(expr: str):\n    return eval(expr)\n"})
	if code != 200 || len(out["findings"].([]any)) != 1 {
		t.Fatalf("test: %d %v", code, out)
	}
	// a bad regex never reaches the disk
	if code, _ := libPost(t, a, "/api/library/save", map[string]any{"kind": "checkers", "name": "my-eval", "text": strings.Replace(checker, `\(`, `(`, 1)}); code != 400 {
		t.Errorf("bad regex saved: %d", code)
	}
	if code, out := libPost(t, a, "/api/library/save", map[string]any{"kind": "checkers", "name": "../My Eval", "text": checker}); code != 200 || out["name"] != "my-eval.yaml" {
		t.Fatalf("save: %d %v", code, out)
	}
	cs, _ := a.checkers()
	found := false
	for _, c := range cs {
		found = found || c.ID == "my-eval"
	}
	if !found {
		t.Fatal("saved checker not loaded")
	}
	libPost(t, a, "/api/library/toggle", map[string]any{"kind": "checkers", "name": "my-eval.yaml", "enabled": false})
	cs, _ = a.checkers()
	for _, c := range cs {
		if c.ID == "my-eval" {
			t.Error("switched-off checker still loaded")
		}
	}
	// bundled files can only be switched off, not removed
	if code, _ := libPost(t, a, "/api/library/remove", map[string]any{"kind": "checkers", "name": "shell-from-input.yaml"}); code != 404 {
		t.Errorf("removed a bundled file: %d", code)
	}
	if code, _ := libPost(t, a, "/api/library/remove", map[string]any{"kind": "checkers", "name": "my-eval.yaml"}); code != 200 {
		t.Fatalf("remove: %d", code)
	}
	if _, err := os.Stat(filepath.Join(a.base, "checkers", "my-eval.yaml")); !os.IsNotExist(err) {
		t.Error("file still there")
	}
	if m, _ := filepath.Glob(filepath.Join(a.base, "checkers", ".trash", "my-eval.yaml.*")); len(m) != 1 {
		t.Error("not moved to .trash")
	}
}

func TestLibraryDorkIDClash(t *testing.T) {
	a := testApp(t)
	code, out := libPost(t, a, "/api/library/save", map[string]any{"kind": "dorks", "name": "mine", "text": "id: mcp\nname: Mine\nqueries: [{q: 'topic:x'}]\n"})
	if code != 400 || !strings.Contains(out["error"].(string), "already used") {
		t.Errorf("clash accepted: %d %v", code, out)
	}
}

func TestSemgrepFileCheck(t *testing.T) {
	if err := checkSemgrepFile([]byte("rules:\n  - id: x\n    languages: [python]\n    message: m\n    pattern: eval(...)\n")); err == nil {
		t.Error("rule without metadata.class accepted")
	}
	if err := checkSemgrepFile([]byte("rules:\n  - id: x\n    languages: [python]\n    message: m\n    metadata: {class: code-exec}\n    pattern: eval(...)\n")); err != nil {
		t.Error(err)
	}
}

func TestConvertKeepsReadableOrder(t *testing.T) {
	n := orderedYAML(map[string]any{"queries": []any{map[string]any{"q": "x", "id": "a"}}, "name": "N", "id": "i", "zzz": 1, "message": ""})
	var keys []string
	for i := 0; i < len(n.Content); i += 2 {
		keys = append(keys, n.Content[i].Value)
	}
	if strings.Join(keys, ",") != "id,name,queries,zzz" {
		t.Errorf("keys = %v", keys)
	}
}
