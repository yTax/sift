package main

import (
	"math"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	checkerCases = append(checkerCases, []struct {
		checker, name, file, src string
		want                     bool
	}{
		{proxyChecker, "next catch-all adds a service token and checks nobody", "app/api/agent/[...path]/route.ts", `
const API = process.env.AGENT_URL;
const TOKEN = process.env.AGENT_TOKEN || "";
export async function GET(req, context) {
  const { path } = await context.params;
  const resp = await fetch(API + "/" + path.join("/"), {
    headers: { "X-API-Key": TOKEN },
  });
  return resp;
}`, true},
		{proxyChecker, "same proxy checks the session first", "app/api/agent/[...path]/route.ts", `
const TOKEN = process.env.AGENT_TOKEN || "";
export async function GET(req, context) {
  const session = await getServerSession();
  if (!session) return new Response("no", { status: 401 });
  const { path } = await context.params;
  return fetch(API + "/" + path.join("/"), { headers: { "X-API-Key": TOKEN } });
}`, false},
		{proxyChecker, "same proxy sends the user's own cookie", "app/api/agent/[...path]/route.ts", `
export async function GET(req, context) {
  const { path } = await context.params;
  const userToken = req.cookies.get("t");
  return fetch(API + "/" + path.join("/"), { headers: { "X-API-Key": userToken } });
}`, false},
		{proxyChecker, "express forwards the url with a key", "routes/proxy.js", `
const KEY = process.env.UPSTREAM_KEY;
router.get("/up/*", async (req, res) => {
  const r = await fetch(BASE + req.originalUrl, { headers: { Authorization: KEY } });
  res.send(await r.text());
});`, true},
		{proxyChecker, "fastapi path proxy with an environment key", "api/proxy.py", `
import os, httpx
KEY = os.environ["UPSTREAM_KEY"]
@app.get("/up/{rest:path}")
async def up(rest: str):
    return await httpx.get(f"{BASE}/{rest}", headers={"X-Api-Key": KEY})
`, true},
		{proxyChecker, "fastapi path proxy with a login dependency", "api/proxy.py", `
import os, httpx
KEY = os.environ["UPSTREAM_KEY"]
@app.get("/up/{rest:path}")
async def up(rest: str, user = Depends(get_current_user)):
    return await httpx.get(f"{BASE}/{rest}", headers={"X-Api-Key": KEY})
`, false},
	}...)
}

func traceOf(t *testing.T, name, src, checker string) []TraceStep {
	t.Helper()
	checkers, _ := loadCheckers(filepath.Join(t.TempDir(), "none"))
	for _, f := range checkFileLib(name, []byte(src), checkers, false) {
		if f.Checker == checker {
			return f.Trace
		}
	}
	t.Fatalf("%s did not fire", checker)
	return nil
}

func TestTraceFollowsAssignments(t *testing.T) {
	tr := traceOf(t, "files.js", `
app.get("/f", (req, res) => {
  const name = req.query.name;
  const full = path.join(ROOT, name);
  const other = 1;
  res.sendFile(full);
});`, "tool-path-to-fs")
	var kinds []string
	for _, s := range tr {
		kinds = append(kinds, s.Kind)
	}
	if got := strings.Join(kinds, " "); got != "input step sink" {
		t.Fatalf("kinds = %q (%+v)", got, tr)
	}
	if !strings.Contains(tr[0].Text, "req.query.name") || tr[0].Line != 3 || tr[2].Line != 6 {
		t.Errorf("trace = %+v", tr)
	}
}

func TestPlainStringDoesNotTaint(t *testing.T) {
	checkers, _ := loadCheckers(filepath.Join(t.TempDir(), "none"))
	src := `
@app.get("/x")
def x(graph: str):
    scope = lookup("graph:write")
    return open(scope).read()
`
	for _, f := range checkFileLib("x.py", []byte(src), checkers, false) {
		if f.Checker == "tool-path-to-fs" {
			t.Errorf("fired through a word in a string: %+v", f)
		}
	}
}

func TestTraceGoesIntoHelper(t *testing.T) {
	tr := traceOf(t, "h.py", `
from flask import request
def _load(p):
    return open(p).read()
def view():
    return _load(request.args["f"])
`, "tool-path-to-fs")
	if len(tr) != 2 || tr[0].Kind != "call" || tr[1].Kind != "sink" || !strings.Contains(tr[1].Text, "open(p)") {
		t.Errorf("trace = %+v", tr)
	}
}

func TestFindingsWeightCountsCauses(t *testing.T) {
	one := Finding{Checker: "c", Path: "a.py", Func: "f", Via: "x", Weight: 4, Confidence: "high"}
	var same []Finding
	for i := 0; i < 20; i++ {
		f := one
		f.Line = i
		same = append(same, f)
	}
	if got := findingsWeight(same); got != 4 {
		t.Errorf("twenty lines of one cause = %v, want 4", got)
	}
	two := one
	two.Func = "g"
	if got := findingsWeight([]Finding{one, two}); math.Abs(got-(4+4*causeDecay)) > 1e-9 {
		t.Errorf("two causes = %v", got)
	}
	helper := []Finding{{Checker: "c", Path: "a.py", Func: "f", Via: "x", Through: "h", Weight: 4}, {Checker: "c", Path: "a.py", Func: "g", Via: "y", Through: "h", Weight: 4}}
	if got := findingsWeight(helper); got != 4 {
		t.Errorf("one helper from two handlers = %v, want 4", got)
	}
	confirmed := one
	confirmed.Confirmed = true
	if got := findingsWeight([]Finding{one, confirmed}); got != 6 {
		t.Errorf("confirmed member lifts its cause: %v, want 6", got)
	}
}

func TestEvidenceCapsVolume(t *testing.T) {
	s := defaultSettings()
	s.Weights = Weights{Sinks: 3, Surface: 2, Auth: 2, Findings: 4}
	r := &Repo{Scan: &ScanResult{WeightedSinks: 5000, SurfaceHits: 5000, AuthHits: 5000}}
	noFinding := computeScore(r, s, false).Total
	if noFinding > 100*evidenceFloor {
		t.Errorf("volume alone scored %v", noFinding)
	}
	r.Scan.Findings = []Finding{{Checker: "c", Path: "a", Func: "f", Via: "x", Weight: 4, Confidence: "high"}}
	if with := computeScore(r, s, false).Total; with <= noFinding {
		t.Errorf("a finding should raise the score: %v vs %v", with, noFinding)
	}
}

func TestPrecisionStatus(t *testing.T) {
	checkers, _ := loadCheckers(filepath.Join(t.TempDir(), "none"))
	src := []byte(`
app.get("/f", (req, res) => {
  res.sendFile(req.query.name);
});`)
	l := PrecisionLabel{Path: "f.js", Checker: "tool-path-to-fs", Match: "res.sendFile(req.query.name)"}
	if got := precisionStatus(l, src, checkers); got != "fired" {
		t.Errorf("status = %s", got)
	}
	l.Match = "gone from the file"
	if got := precisionStatus(l, src, checkers); got != "stale" {
		t.Errorf("status = %s", got)
	}
	l.Match, l.Checker = "res.sendFile(req.query.name)", "sql-from-input"
	if got := precisionStatus(l, src, checkers); got != "quiet" {
		t.Errorf("status = %s", got)
	}
	labels, err := loadPrecisionLabels()
	if err != nil || len(labels) == 0 {
		t.Fatalf("labels: %v, %v", labels, err)
	}
	for _, l := range labels {
		if l.Label != "real" && l.Label != "false" || l.Repo == "" || l.Path == "" || l.Match == "" || l.Why == "" {
			t.Errorf("bad label %+v", l)
		}
	}
}
