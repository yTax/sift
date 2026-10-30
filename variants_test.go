package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseFixRefs(t *testing.T) {
	links := []string{
		"https://github.com/acme/tool/security/advisories/GHSA-aaaa-bbbb-cccc",
		"https://github.com/acme/tool/pull/12",
		"https://github.com/acme/tool/commit/0123456789abcdef0123456789abcdef01234567",
		"https://github.com/acme/tool/pull/12/commits/89abcdef0",
		"https://github.com/acme/tool/commit/0123456789abcdef0123456789abcdef01234567",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-1",
	}
	got := parseFixRefs(links)
	want := []fixRef{
		{owner: "acme", repo: "tool", sha: "0123456789abcdef0123456789abcdef01234567"},
		{owner: "acme", repo: "tool", sha: "89abcdef0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("commits: got %+v, want %+v", got, want)
	}
	// no commit linked: fall back to the pull request
	got = parseFixRefs([]string{"https://github.com/acme/tool/pull/12", "https://example.com/x"})
	if len(got) != 1 || got[0].pr != 12 || got[0].url() != "https://github.com/acme/tool/pull/12" {
		t.Errorf("pr fallback: got %+v", got)
	}
}

const variantPatch = `@@ -10,8 +10,12 @@ server.tool("read_note", { name: z.string() }, async ({ name }) => {
   const notesDir = getNotesDirectory();
-  const notePath = path.join(notesDir, name);
-  const text = await fs.readFile(notePath, "utf8");
+  const notePath = path.resolve(notesDir, name);
+  if (!notePath.startsWith(notesDir + path.sep)) {
+    throw new Error("outside the notes folder");
+  }
+  const text = await fs.readFile(notePath, "utf8");
   // keep going
-  // old comment
   return { content: [{ type: "text", text }] };
 });`

func TestRemovedLines(t *testing.T) {
	checkers, _ := loadCheckers(filepath.Join(t.TempDir(), "none"))
	files := []ghPatchFile{
		{Filename: "src/notes.ts", Patch: variantPatch},
		{Filename: "test/notes.test.ts", Patch: "-const x = readFileSync(evilPathFromTest)"},
		{Filename: "README.md", Patch: "-use readFile on any path"},
	}
	lines := removedLines(files, checkers)
	var texts []string
	for _, l := range lines {
		texts = append(texts, l.Text)
	}
	// the readFile line came back unchanged in the fix, the comment is not code, tests and docs
	// are skipped: only the join is the pre-fix shape
	if len(lines) == 0 || lines[0].Text != "const notePath = path.join(notesDir, name);" {
		t.Fatalf("removed lines = %q", texts)
	}
	for _, l := range lines {
		if strings.Contains(l.Text, "old comment") || strings.Contains(l.Path, "test") || strings.HasSuffix(l.Path, ".md") {
			t.Errorf("kept %s: %q", l.Path, l.Text)
		}
	}
	qs := variantQueries(lines)
	if len(qs) == 0 {
		t.Fatal("no queries")
	}
	if q := qs[0].String(); !strings.Contains(q, "notesDir") || !strings.HasSuffix(q, "language:TypeScript") {
		t.Errorf("first query = %q", q)
	}
}

// A fix that only adds a check removes nothing; the unchanged sink it now guards is the shape.
func TestRemovedLinesGuardOnlyFix(t *testing.T) {
	checkers, _ := loadCheckers(filepath.Join(t.TempDir(), "none"))
	patch := `@@ -1,4 +1,7 @@ def fetch_page(url):
 def fetch_page(url):
+    if urlparse(url).hostname in BLOCKED_HOSTS:
+        raise ValueError("blocked")
     resp = requests.get(url, timeout=PAGE_TIMEOUT)
     return resp.text`
	lines := removedLines([]ghPatchFile{{Filename: "tools/web.py", Patch: patch}}, checkers)
	if len(lines) == 0 || !lines[0].Sink || !lines[0].Context || !strings.Contains(lines[0].Text, "requests.get") {
		t.Fatalf("lines = %+v", lines)
	}
}

func TestDistinctiveWords(t *testing.T) {
	got := distinctiveWords(`const full = path.join(workspaceRoot, args.relPath, "fixed/sub/dir");`, map[string]bool{"workspaceroot": true})
	// relPath is gone from the fixed code, so it beats the longer workspaceRoot; stop words and
	// string contents are dropped
	want := []string{"relPath", "workspaceRoot", "full"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestVariantQueryNarrowing(t *testing.T) {
	q := variantQuery{words: []string{"a1b2", "c3d4", "e5f6", "g7h8"}, file: "x.go", used: 3}
	if s := q.String(); s != "a1b2 c3d4 e5f6 language:Go" {
		t.Errorf("query = %q", s)
	}
	q.used++
	if s := q.String(); s != "a1b2 c3d4 e5f6 g7h8 language:Go" {
		t.Errorf("narrowed = %q", s)
	}
}
