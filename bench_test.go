package main

import (
	"path/filepath"
	"testing"
)

func TestChangedLines(t *testing.T) {
	patch := `@@ -10,4 +10,6 @@ def read(name):
     base = ROOT
-    p = os.path.join(base, name)
+    p = os.path.realpath(os.path.join(base, name))
+    if not p.startswith(base + os.sep):
+        raise ValueError
     return open(p).read()`
	old, new := changedLines(patch)
	if !old[11] || old[10] || old[13] {
		t.Errorf("old = %v", old)
	}
	if !new[11] || !new[12] || !new[13] || new[14] {
		t.Errorf("new = %v", new)
	}
}

func TestBenchEvalCase(t *testing.T) {
	checkers, _ := loadCheckers(filepath.Join(t.TempDir(), "none"))
	before := `import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("files")

@mcp.tool()
def read_note(name: str) -> str:
    p = os.path.join(NOTES, name)
    return open(p).read()
`
	after := `import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("files")

@mcp.tool()
def read_note(name: str) -> str:
    p = os.path.realpath(os.path.join(NOTES, name))
    if os.path.commonpath([p, NOTES]) != NOTES:
        raise ValueError("outside")
    return open(p).read()
`
	patch := `@@ -6,3 +6,5 @@ def read_note(name: str) -> str:
 def read_note(name: str) -> str:
-    p = os.path.join(NOTES, name)
+    p = os.path.realpath(os.path.join(NOTES, name))
+    if os.path.commonpath([p, NOTES]) != NOTES:
+        raise ValueError("outside")
     return open(p).read()`
	c := &BenchCase{GHSA: "GHSA-aaaa-aaaa-aaaa", Classes: []string{"path-traversal"},
		Files: []BenchFile{{Path: "server.py", Patch: patch, Before: before, After: after}}}
	if r := benchEvalCase(c, checkers); r.Result != "cleared" {
		t.Errorf("result = %+v", r)
	}
	// the same fix seen as SSRF: caught by nothing of that class, but a checker fired there
	c.Classes = []string{"ssrf"}
	if r := benchEvalCase(c, checkers); r.Result != "other" || len(r.Removed) == 0 {
		t.Errorf("result = %+v", r)
	}
	// a fix the checker doesn't understand leaves the finding in place
	c.Classes = []string{"path-traversal"}
	c.Files[0].After = before
	if r := benchEvalCase(c, checkers); r.Result != "still" {
		t.Errorf("result = %+v", r)
	}
	rep := BenchScore([]*BenchCase{c}, checkers)
	if rep.Caught != 1 || rep.Classes[0].StillAfter != 1 {
		t.Errorf("report = %+v", rep)
	}
}
