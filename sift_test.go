package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func defaultsDir(t *testing.T, sub string) string {
	t.Helper()
	d := filepath.Join("defaults", sub)
	if _, err := os.Stat(d); err != nil {
		t.Fatalf("missing %s: %v", d, err)
	}
	return d
}

func TestDefaultDorksLoad(t *testing.T) {
	cats, errs := loadCategories(defaultsDir(t, "dorks"))
	for _, e := range errs {
		t.Errorf("%s: %s", e.File, e.Error)
	}
	if len(cats) < 8 {
		t.Fatalf("expected at least 8 categories, got %d", len(cats))
	}
	profiles, perrs := loadSinkProfiles(defaultsDir(t, "sinks"))
	for _, e := range perrs {
		t.Errorf("%s: %s", e.File, e.Error)
	}
	ids := map[string]bool{}
	for _, p := range profiles {
		ids[p.ID] = true
	}
	s := defaultSettings()
	for _, c := range cats {
		for _, sid := range c.Sinks {
			if !ids[sid] {
				t.Errorf("category %s references unknown sink profile %q", c.ID, sid)
			}
		}
		if c.Source == "github" {
			for _, q := range c.Queries {
				full := c.FullQuery(q, s)
				if strings.Contains(full, "{{") {
					t.Errorf("%s/%s: unexpanded template: %s", c.ID, q.ID, full)
				}
				if strings.Contains(full, "fork:false") {
					t.Errorf("%s/%s: fork:false is not a real qualifier", c.ID, q.ID)
				}
			}
		}
		f := c.Flags(s)
		if c.Source != "github" && f.Require {
			t.Errorf("%s: program-handled source should not require contacts", c.ID)
		}
	}
}

// match returns the labels of every pattern (of the given kind) that matches line.
func match(p *SinkProfile, kind, line string) []string {
	var list []Pattern
	switch kind {
	case "sink":
		list = p.Sinks
	case "surface":
		list = p.Surface
	case "auth":
		list = p.Auth
	}
	var out []string
	for _, pt := range list {
		if pt.re.MatchString(line) {
			out = append(out, pt.Class+":"+pt.Label)
		}
	}
	return out
}

func TestSinkPatterns(t *testing.T) {
	profiles, errs := loadSinkProfiles(defaultsDir(t, "sinks"))
	if len(errs) > 0 {
		t.Fatalf("profile errors: %+v", errs)
	}
	byID := map[string]*SinkProfile{}
	for _, p := range profiles {
		byID[p.ID] = p
	}
	type tc struct {
		profile, kind, line, wantClass string // wantClass "" = must NOT match any pattern of that kind
	}
	cases := []tc{
		// JS: real command execution vs. regex .exec()
		{"js-ts", "sink", `const { exec } = require('child_process')`, "cmd-exec"},
		{"js-ts", "sink", `child_process.exec("ffmpeg " + name)`, "cmd-exec"},
		{"js-ts", "sink", `  exec(cmd, (err) => {})`, "cmd-exec"},
		{"js-ts", "sink", `const m = /(\d+)/.exec(str)`, ""},
		{"js-ts", "sink", `while ((m = re.exec(text)) !== null) {`, ""},
		{"js-ts", "sink", `const out = path.join(root, req.query.file)`, "path-traversal"},
		{"js-ts", "sink", `const r = await fetch(url)`, "ssrf"},
		{"js-ts", "sink", `const r = await fetch("https://api.example.com/x")`, ""},
		{"js-ts", "sink", `await prisma.$queryRawUnsafe(q)`, "sqli"},
		{"js-ts", "sink", "db.query(`SELECT * FROM u WHERE id=${id}`)", "sqli"},
		{"js-ts", "sink", `const x = JSON.parse(evaluation)`, ""},
		{"js-ts", "surface", `server.tool("read_file", schema, async ({ path }) => {`, ""},
		// Python
		{"python", "sink", `subprocess.run(cmd, shell=True)`, "cmd-exec"},
		{"python", "sink", `data = pickle.loads(blob)`, "deserialization"},
		{"python", "sink", `x = ast.literal_eval(s)`, ""},
		{"python", "sink", `cursor.execute(f"SELECT * FROM t WHERE id={uid}")`, "sqli"},
		{"python", "sink", `cursor.execute("SELECT * FROM t WHERE id=%s", (uid,))`, ""},
		{"python", "sink", `return send_from_directory(base, name)`, "path-traversal"},
		{"python", "surface", `@mcp.tool()`, ""},
		// Go
		{"go", "sink", `cmd := exec.Command("sh", "-c", userCmd)`, "cmd-exec"},
		{"go", "sink", `p := filepath.Join(root, r.URL.Query().Get("f"))`, "path-traversal"},
		{"go", "sink", `rows, err := db.Query(fmt.Sprintf("SELECT * FROM t WHERE n='%s'", n))`, "sqli"},
		{"go", "sink", `resp, err := http.Get("https://example.com")`, ""},
		// Java / Jenkins / Minecraft
		{"java", "sink", `ObjectInputStream ois = new ObjectInputStream(in);`, "deserialization"},
		{"java", "sink", `Process p = Runtime.getRuntime().exec(cmd);`, "cmd-exec"},
		{"java", "sink", `private String apiToken;`, "plaintext-secret"},
		{"java", "sink", `private Secret apiToken;`, ""},
		{"java", "sink", `DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();`, "xxe"},
		{"java", "surface", `public FormValidation doCheckUrl(@QueryParameter String value) {`, ""},
		{"java", "auth", `Jenkins.get().checkPermission(Jenkins.ADMINISTER);`, ""},
		// PHP / WordPress
		{"php", "sink", `'permission_callback' => '__return_true',`, "missing-auth"},
		{"php", "sink", `$data = unserialize( $_POST['d'] );`, "deserialization"},
		{"php", "sink", `$x = maybe_unserialize( $meta );`, "deserialization"},
		{"php", "sink", `$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE id = $id" );`, "sqli"},
		{"php", "sink", `$wpdb->get_results( $wpdb->prepare( "SELECT * FROM t WHERE id = %d", $id ) );`, ""},
		{"php", "sink", `update_option( $_POST['key'], $_POST['value'] );`, "privesc"},
		{"php", "sink", `$stmt->execute();`, ""},
		{"php", "sink", `include $template;`, "file-inclusion"},
		{"php", "sink", `include 'views/header.php';`, ""},
		{"php", "surface", `add_action( 'wp_ajax_nopriv_my_action', 'handler' );`, ""},
		// C/C++
		{"c-cpp", "sink", `strcpy(buf, input);`, "memory"},
		{"c-cpp", "sink", `printf(msg);`, "format-string"},
		{"c-cpp", "sink", `printf("%s", msg);`, ""},
		// Extensions & Electron
		{"browser-extension", "sink", `chrome.runtime.onMessageExternal.addListener((msg, sender) => {`, "ext-messaging"},
		{"browser-extension", "auth", `if (event.origin !== "https://example.com") return;`, ""},
		{"electron", "sink", `webPreferences: { nodeIntegration: true, contextIsolation: false }`, "electron-config"},
		{"electron", "sink", `shell.openExternal(url)`, "open-external"},
		{"electron", "sink", `win.loadURL('https://app.local')`, ""},
	}
	for _, c := range cases {
		p := byID[c.profile]
		if p == nil {
			t.Fatalf("no profile %s", c.profile)
		}
		got := match(p, c.kind, c.line)
		switch {
		case c.kind != "sink":
			if len(got) == 0 {
				t.Errorf("[%s %s] expected a match for %q", c.profile, c.kind, c.line)
			}
		case c.wantClass == "":
			if len(got) > 0 {
				t.Errorf("[%s] false positive on %q: %v", c.profile, c.line, got)
			}
		default:
			ok := false
			for _, g := range got {
				if strings.HasPrefix(g, c.wantClass+":") {
					ok = true
				}
			}
			if !ok {
				t.Errorf("[%s] %q: want class %s, got %v", c.profile, c.line, c.wantClass, got)
			}
		}
	}
}

func TestIsTestPath(t *testing.T) {
	yes := []string{"src/test/java/FooTest.java", "pkg/handler_test.go", "app/tests/test_api.py", "web/Button.spec.tsx", "conftest.py", "src/main/java/FooIT.java"}
	no := []string{"scripts/latest_release.py", "pkg/contest.go", "src/main/java/Latest.java", "src/Contest.kt", "lib/attestation.js"}
	for _, p := range yes {
		if !shouldSkip(p, true, nil) {
			t.Errorf("%s should be treated as a test", p)
		}
	}
	for _, p := range no {
		if shouldSkip(p, true, nil) {
			t.Errorf("%s should NOT be treated as a test", p)
		}
	}
}

func TestCleanEmail(t *testing.T) {
	keep := []string{"poweruser@proton.me", "contest@club.dev", "security@acme.io", "admin@mysite.org"}
	drop := []string{"user@domain.com", "test@foo.dev", "logo@2x.png", "noreply@acme.io", "x@users.noreply.github.com", "you@example.com"}
	for _, e := range keep {
		if _, ok := cleanEmail(e); !ok {
			t.Errorf("dropped real email %s", e)
		}
	}
	for _, e := range drop {
		if _, ok := cleanEmail(e); ok {
			t.Errorf("kept junk email %s", e)
		}
	}
}

func TestContactsFromText(t *testing.T) {
	var cs contactSet
	cs.scanText(`Join us: https://discord.gg/abc123 · t.me/mychan · follow https://x.com/someone · mail dev@proj.io
Share: https://twitter.com/intent/tweet?text=hi`, "README")
	kinds := map[string]string{}
	for _, c := range cs.list {
		kinds[c.Kind] = c.Value
	}
	for _, k := range []string{"discord", "telegram", "twitter", "email"} {
		if kinds[k] == "" {
			t.Errorf("missing %s contact in %+v", k, cs.list)
		}
	}
	if kinds["twitter"] != "@someone" {
		t.Errorf("twitter intent link leaked through: %v", kinds["twitter"])
	}
}

func TestUnscannedRanksBelowScanned(t *testing.T) {
	s := defaultSettings()
	now := time.Now()
	pvr := true
	meta := &Enrichment{PushedAt: now, MaintainerLastReply: &now, IssuesSeen: 5, PVR: &pvr}
	unscanned := &Repo{Source: "github", Enriched: meta, Contacts: []Contact{{Kind: "pvr"}}}
	scanned := &Repo{Source: "github", Enriched: meta, Contacts: []Contact{{Kind: "pvr"}},
		Scan: &ScanResult{WeightedSinks: 12, SurfaceHits: 15, AuthHits: 6}}
	a := computeScore(unscanned, s, false)
	b := computeScore(scanned, s, false)
	if !a.Partial {
		t.Error("unscanned score should be partial")
	}
	if a.Total >= b.Total {
		t.Errorf("unscanned (%.1f) should rank below scanned (%.1f)", a.Total, b.Total)
	}
}

func TestFilters(t *testing.T) {
	s := defaultSettings()
	old := time.Now().AddDate(0, 0, -200)
	r := &Repo{Source: "github", Enriched: &Enrichment{PushedAt: old, IssuesSeen: 4}}
	f := applyFilters(r, s, true)
	if f.Pass {
		t.Fatal("stale repo with no contact should be filtered")
	}
	joined := strings.Join(f.Reasons, "|")
	for _, want := range []string{"no push", "no releases", "no maintainer reply", "no private contact"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing reason %q in %v", want, f.Reasons)
		}
	}
	// Jenkins plugin with a dead maintainer must still pass: the security team handles it.
	jk := &Repo{Source: "jenkins", Enriched: &Enrichment{PushedAt: old, IssuesSeen: 4, Releases: 3}}
	if f := applyFilters(jk, s, false); !f.Pass {
		t.Errorf("jenkins plugin should pass, got %v", f.Reasons)
	}
}

func TestScanZip(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "repo.zip")
	f, _ := os.Create(zp)
	zw := zip.NewWriter(f)
	add := func(name, body string) {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	add("owner-repo-abc/src/server.js", "const { exec } = require('child_process')\napp.post('/run', (req, res) => {\n  exec(req.body.cmd)\n})\n")
	add("owner-repo-abc/node_modules/x/index.js", "eval(x)\n")
	add("owner-repo-abc/src/server.test.js", "exec('ls')\n")
	add("owner-repo-abc/README.md", "exec(x)\n")
	zw.Close()
	f.Close()

	profiles, _ := loadSinkProfiles(defaultsDir(t, "sinks"))
	var js []*SinkProfile
	for _, p := range profiles {
		if p.ID == "js-ts" {
			js = append(js, p)
		}
	}
	res, err := scanZip(zp, scanOpts{Profiles: js, SkipTests: true, MaxFileSize: 1 << 20, StripPrefix: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 {
		t.Errorf("expected only src/server.js scanned, got %d files", res.Files)
	}
	if res.SinkHits < 2 || res.SurfaceHits < 1 {
		t.Errorf("expected sink+surface hits, got sinks=%d surface=%d", res.SinkHits, res.SurfaceHits)
	}
	for _, h := range res.Hits {
		if strings.HasPrefix(h.Path, "owner-repo-abc") {
			t.Errorf("prefix not stripped: %s", h.Path)
		}
	}
}

func TestCVEPath(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		r    *Repo
		want string
	}{
		{"pvr on", &Repo{Source: "github", Enriched: &Enrichment{PVR: &yes}}, "github-pvr"},
		{"past ghsas", &Repo{Source: "github", Enriched: &Enrichment{PVR: &no, Advisories: 2}}, "github-advisory"},
		{"security.md only", &Repo{Source: "github", Enriched: &Enrichment{HasSecurityPolicy: true}}, "security-policy"},
		{"email only", &Repo{Source: "github", Enriched: &Enrichment{}, Contacts: []Contact{{Kind: "email"}}}, "mitre"},
		{"website only", &Repo{Source: "github", Enriched: &Enrichment{}, Contacts: []Contact{{Kind: "website"}}}, "none"},
		{"wordpress", &Repo{Source: "wordpress"}, "wordpress-cna"},
		{"jenkins", &Repo{Source: "jenkins"}, "jenkins-cna"},
		{"not enriched", &Repo{Source: "github"}, ""},
	}
	for _, c := range cases {
		if got, _ := cvePath(c.r); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCVEPathToggle(t *testing.T) {
	now := time.Now()
	yes, no := true, false
	scan := &ScanResult{WeightedSinks: 12, SurfaceHits: 15, AuthHits: 6}
	// same code and metadata; only how a finding would become a CVE differs
	withCNA := &Repo{Source: "github", Scan: scan, Enriched: &Enrichment{PushedAt: now, PVR: &yes}}
	without := &Repo{Source: "github", Scan: scan, Enriched: &Enrichment{PushedAt: now, PVR: &no}}

	s := defaultSettings()
	if !s.ScoreCVEPath {
		t.Fatal("cve_path scoring should be on by default")
	}
	a, b := computeScore(withCNA, s, false), computeScore(without, s, false)
	if _, ok := a.Parts["cve_path"]; !ok {
		t.Fatal("cve_path part missing with the toggle on")
	}
	if a.Total <= b.Total {
		t.Errorf("repo with a CNA route (%.1f) should outrank one without (%.1f)", a.Total, b.Total)
	}

	s.ScoreCVEPath = false
	if _, ok := computeScore(withCNA, s, false).Parts["cve_path"]; ok {
		t.Error("cve_path part present with the toggle off")
	}
}

func TestRunIDsStayUniquePastCap(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	var last int
	for i := 0; i < 130; i++ {
		last = st.AddRun(RunRecord{})
		if seen[last] {
			t.Fatalf("run %d got duplicate id %d", i, last)
		}
		seen[last] = true
	}
	st.FinishRun(last, func(r *RunRecord) { r.Outcome = "finished" })
	n := 0
	for _, r := range st.Runs() {
		if r.Outcome == "finished" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("FinishRun touched %d runs, want 1", n)
	}
}

func TestLoadDotEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	body := "# comment\nSIFT_T_A=plain\nexport SIFT_T_B=\"quoted\"\nSIFT_T_EMPTY=\nSIFT_T_KEEP=fromfile\nnot a pair\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIFT_T_KEEP", "fromenv")
	for _, k := range []string{"SIFT_T_A", "SIFT_T_B", "SIFT_T_EMPTY"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	if err := loadDotEnv(p); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"SIFT_T_A": "plain", "SIFT_T_B": "quoted", "SIFT_T_KEEP": "fromenv"}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if _, set := os.LookupEnv("SIFT_T_EMPTY"); set {
		t.Error("empty value should not be set")
	}
	if err := loadDotEnv(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Errorf("missing file: %v", err)
	}
}

// Same totals, different layout: the repo whose route and exec share a file must rank higher.
func TestPairingOutranksScattered(t *testing.T) {
	profiles, _ := loadSinkProfiles(defaultsDir(t, "sinks"))
	var js []*SinkProfile
	for _, p := range profiles {
		if p.ID == "js-ts" {
			js = append(js, p)
		}
	}
	build := func(files map[string]string) *ScanResult {
		zp := filepath.Join(t.TempDir(), "repo.zip")
		f, _ := os.Create(zp)
		zw := zip.NewWriter(f)
		for name, body := range files {
			w, _ := zw.Create("o-r-abc/" + name)
			w.Write([]byte(body))
		}
		zw.Close()
		f.Close()
		res, err := scanZip(zp, scanOpts{Profiles: js, SkipTests: true, MaxFileSize: 1 << 20, StripPrefix: true})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	route := "app.post('/run', (req, res) => {\n  res.send('ok')\n})\n"
	sink := "const { exec } = require('child_process')\nexec(cmd)\n"
	paired := build(map[string]string{"src/a.js": route + sink, "src/b.js": "const x = 1\n"})
	scattered := build(map[string]string{"src/a.js": route, "src/b.js": sink})

	if paired.SinkHits != scattered.SinkHits || paired.SurfaceHits != scattered.SurfaceHits {
		t.Fatalf("fixtures should have equal totals: paired %d/%d, scattered %d/%d",
			paired.SinkHits, paired.SurfaceHits, scattered.SinkHits, scattered.SurfaceHits)
	}
	if paired.PairedFiles != 1 || len(paired.HotFiles) != 1 || paired.HotFiles[0].Path != "src/a.js" || !paired.HotFiles[0].Near {
		t.Errorf("paired: files=%d hot=%+v", paired.PairedFiles, paired.HotFiles)
	}
	if scattered.PairedFiles != 0 || scattered.PairedWeight != 0 {
		t.Errorf("scattered should not pair: files=%d weight=%v", scattered.PairedFiles, scattered.PairedWeight)
	}
	s := defaultSettings()
	enr := &Enrichment{PushedAt: time.Now()}
	sp := computeScore(&Repo{Source: "github", Scan: paired, Enriched: enr}, s, false)
	ss := computeScore(&Repo{Source: "github", Scan: scattered, Enriched: enr}, s, false)
	if sp.Total <= ss.Total {
		t.Errorf("paired %.1f should outrank scattered %.1f", sp.Total, ss.Total)
	}
}

// Rebuilding pairing from stored hits (old scans) must match what the scanner records.
func TestPairHitsFromStoredHits(t *testing.T) {
	hits := []Hit{
		{Path: "a.go", Line: 10, Kind: "surface"},
		{Path: "a.go", Line: 30, Kind: "sink", Label: "exec", Class: "cmd-exec", Weight: 2},
		{Path: "a.go", Line: 400, Kind: "sink", Label: "open", Class: "file-io", Weight: 1},
		{Path: "b.go", Line: 5, Kind: "sink", Label: "exec", Class: "cmd-exec", Weight: 2},
	}
	n, w, hot := pairHits(hits)
	if n != 1 || len(hot) != 1 || hot[0].Path != "a.go" {
		t.Fatalf("n=%d hot=%+v", n, hot)
	}
	if w != 4 { // 2*1.5 near + 1 far
		t.Errorf("weight = %v, want 4", w)
	}
	if strings.Join(hot[0].Classes, ",") != "cmd-exec,file-io" {
		t.Errorf("classes = %v", hot[0].Classes)
	}
}

// One or two past advisories is the sweet spot; a heavily picked-over repo scores lower.
func TestHistoryPeaks(t *testing.T) {
	s := defaultSettings()
	h := func(n int) float64 {
		return computeScore(&Repo{Source: "github", Enriched: &Enrichment{Advisories: n, PushedAt: time.Now()}}, s, false).Parts["history"]
	}
	if !(h(1) > h(0) && h(2) > h(5) && h(5) > h(15)) {
		t.Errorf("history: 0=%v 1=%v 2=%v 5=%v 15=%v", h(0), h(1), h(2), h(5), h(15))
	}
}
