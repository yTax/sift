package main

import (
	"testing"
)

// Each case is a small handler in the shape of real MCP/web bugs. vuln must produce the
// checker's finding; the fixed twin must not.
var checkerCases = []struct {
	checker, name, file, src string
	want                     bool
}{
	// --- tool-path-to-fs ---
	{"tool-path-to-fs", "ts mcp tool reads arg", "src/index.ts", `
server.tool("read_file", "Read a file", { path: z.string() }, async ({ path }) => {
  const full = join(ROOT, path);
  const text = await fs.readFile(full, "utf8");
  return { content: [{ type: "text", text }] };
});`, true},
	{"tool-path-to-fs", "ts mcp tool validates path", "src/index.ts", `
server.tool("read_file", "Read a file", { path: z.string() }, async ({ path }) => {
  const full = await validatePath(path);
  const text = await fs.readFile(full, "utf8");
  return { content: [{ type: "text", text }] };
});`, false},
	{"tool-path-to-fs", "express sendFile from query", "server.js", `
app.get('/download', (req, res) => {
  const name = req.query.file;
  res.sendFile(path.join(__dirname, 'files', name));
});`, true},
	{"tool-path-to-fs", "helper with a path param is not a handler", "lib.js", `
function loadConfig(p) {
  return fs.readFileSync(p, 'utf8');
}`, false},
	{"tool-path-to-fs", "python fastmcp tool", "server.py", `
@mcp.tool()
def read_file(path: str) -> str:
    full = os.path.join(BASE_DIR, path)
    with open(full) as f:
        return f.read()
`, true},
	{"tool-path-to-fs", "python tool checks commonpath", "server.py", `
@mcp.tool()
def read_file(path: str) -> str:
    full = os.path.realpath(os.path.join(BASE_DIR, path))
    if os.path.commonpath([full, BASE_DIR]) != BASE_DIR:
        raise ValueError("outside")
    with open(full) as f:
        return f.read()
`, false},
	{"tool-path-to-fs", "go mcp handler", "main.go", `
func handleRead(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	p, err := request.RequireString("path")
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(root, p))
	return mcp.NewToolResultText(string(b)), err
}`, true},
	{"tool-path-to-fs", "go handler uses filepath.Rel", "main.go", `
func handleRead(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	p, _ := request.RequireString("path")
	full := filepath.Join(root, p)
	if rel, err := filepath.Rel(root, full); err != nil || strings.HasPrefix(rel, "..") {
		return nil, errors.New("outside root")
	}
	b, err := os.ReadFile(full)
	return mcp.NewToolResultText(string(b)), err
}`, false},

	// --- prefix-containment ---
	{"prefix-containment", "startsWith on resolved path", "src/paths.ts", `
export function isAllowed(requested: string): boolean {
  const normalizedRequested = path.resolve(requested);
  return allowedDirectories.some((dir) => normalizedRequested.startsWith(path.resolve(dir)) || normalizedRequested.startsWith(allowedDir));
}`, true},
	{"prefix-containment", "startsWith with separator", "src/paths.ts", `
export function isAllowed(requested: string): boolean {
  const r = path.resolve(requested);
  return r === allowedDir || r.startsWith(allowedDir + path.sep);
}`, false},
	{"prefix-containment", "python str startswith base", "fs.py", `
def is_safe(p):
    full = os.path.abspath(p)
    return full.startswith(base_dir)
`, true},
	{"prefix-containment", "url prefix is not a path check", "net.ts", `
function isInternal(url: string) {
  return url.startsWith(baseUrl);
}`, false},

	// --- shell-from-input ---
	{"shell-from-input", "exec with template", "src/tools.ts", `
server.tool("git_log", "log", { repo: z.string() }, async ({ repo }) => {
  const { stdout } = await execAsync(` + "`git -C ${repo} log`" + `);
  exec(` + "`git -C ${repo} log`" + `, cb);
  return { content: [{ type: "text", text: stdout }] };
});`, true},
	{"shell-from-input", "execFile with args array", "src/tools.ts", `
server.tool("git_log", "log", { repo: z.string() }, async ({ repo }) => {
  const { stdout } = await execFileAsync("git", ["-C", repo, "log"]);
  return { content: [{ type: "text", text: stdout }] };
});`, false},
	{"shell-from-input", "python shell=True", "app.py", `
@app.post("/ping")
def ping(host: str):
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return out.stdout
`, true},
	{"shell-from-input", "python shlex.quote", "app.py", `
@app.post("/ping")
def ping(host: str):
    out = subprocess.run(f"ping -c 1 {shlex.quote(host)}", shell=True, capture_output=True)
    return out.stdout
`, false},

	// --- fetch-from-input ---
	{"fetch-from-input", "ts tool fetches url arg", "src/fetch.ts", `
server.tool("fetch", "Fetch a URL", { url: z.string() }, async ({ url }) => {
  const r = await fetch(url);
  return { content: [{ type: "text", text: await r.text() }] };
});`, true},
	{"fetch-from-input", "ts tool checks host allowlist", "src/fetch.ts", `
server.tool("fetch", "Fetch a URL", { url: z.string() }, async ({ url }) => {
  if (!allowedHosts.includes(new URL(url).hostname)) throw new Error("blocked");
  const r = await fetch(url);
  return { content: [{ type: "text", text: await r.text() }] };
});`, false},
	{"fetch-from-input", "flask request.args url", "app.py", `
@app.route("/proxy")
def proxy():
    target = request.args.get("url")
    return requests.get(target).text
`, true},

	// --- code-from-input ---
	{"code-from-input", "python eval of tool arg", "calc.py", `
@mcp.tool()
def calculate(expression: str) -> str:
    return str(eval(expression))
`, true},
	{"code-from-input", "python literal_eval", "calc.py", `
@mcp.tool()
def calculate(expression: str) -> str:
    return str(ast.literal_eval(expression))
`, false},
	{"code-from-input", "yaml.load on body", "api.py", `
@app.post("/import")
def import_cfg(body: bytes):
    cfg = yaml.load(body)
    return cfg
`, true},
	// --- sql-from-input ---
	{"sql-from-input", "express template into query", "routes.js", `
router.get('/user', async (req, res) => {
  const rows = await db.query(` + "`SELECT * FROM users WHERE name = '${req.query.name}'`" + `);
  res.json(rows);
});`, true},
	{"sql-from-input", "express bound parameter", "routes.js", `
router.get('/user', async (req, res) => {
  const rows = await db.query('SELECT * FROM users WHERE name = ?', [req.query.name]);
  res.json(rows);
});`, false},
	{"sql-from-input", "query built in a variable first", "routes.js", `
router.get('/search', async (req, res) => {
  const term = req.query.q;
  const sql = "SELECT id FROM posts WHERE title LIKE '%" + term + "%'";
  res.json(await db.all(sql));
});`, true},
	{"sql-from-input", "python f-string execute", "tools.py", `
@mcp.tool()
def find_user(name: str) -> str:
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return str(cur.fetchall())
`, true},
	{"sql-from-input", "python parameterised execute", "tools.py", `
@mcp.tool()
def find_user(name: str) -> str:
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    return str(cur.fetchall())
`, false},
	{"sql-from-input", "go Sprintf query", "db.go", `
func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	rows, _ := db.Query(fmt.Sprintf("SELECT id FROM items WHERE name = '%s'", q))
	defer rows.Close()
}`, true},
	{"sql-from-input", "wpdb concatenated", "plugin.php", `<?php
function myplugin_ajax_get() {
	global $wpdb;
	$id = $_POST['id'];
	$row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}items WHERE id = $id");
	wp_send_json($row);
}`, true},
	{"sql-from-input", "wpdb prepare", "plugin.php", `<?php
function myplugin_ajax_get() {
	global $wpdb;
	$id = $_POST['id'];
	$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}items WHERE id = %d", $id));
	wp_send_json($row);
}`, false},
	{"sql-from-input", "wpdb with absint", "plugin.php", `<?php
function myplugin_ajax_get() {
	global $wpdb;
	$id = absint($_POST['id']);
	$row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}items WHERE id = $id");
	wp_send_json($row);
}`, false},

	// --- xss-from-input ---
	{"xss-from-input", "php echo of GET", "admin.php", `<?php
function myplugin_page() {
	echo '<input value="' . $_GET['q'] . '">';
}`, true},
	{"xss-from-input", "php echo escaped", "admin.php", `<?php
function myplugin_page() {
	echo '<input value="' . esc_attr($_GET['q']) . '">';
}`, false},
	{"xss-from-input", "php echo of a tainted var", "admin.php", `<?php
function myplugin_page() {
	$tab = $_REQUEST['tab'];
	echo "<h2>Tab: $tab</h2>";
}`, true},

	// --- php variants of the existing checkers ---
	{"tool-path-to-fs", "php include from GET", "loader.php", `<?php
function load_view() {
	include plugin_dir_path(__FILE__) . 'views/' . $_GET['view'] . '.php';
}`, true},
	{"tool-path-to-fs", "php include with basename", "loader.php", `<?php
function load_view() {
	include plugin_dir_path(__FILE__) . 'views/' . basename($_GET['view']) . '.php';
}`, false},
	{"shell-from-input", "php shell_exec", "tools.php", `<?php
function run_ping() {
	$host = $_POST['host'];
	echo shell_exec("ping -c 1 " . $host);
}`, true},
	{"shell-from-input", "php escapeshellarg", "tools.php", `<?php
function run_ping() {
	$host = $_POST['host'];
	echo shell_exec("ping -c 1 " . escapeshellarg($host));
}`, false},
	{"code-from-input", "php unserialize cookie", "cart.php", `<?php
function load_cart() {
	$cart = unserialize(base64_decode($_COOKIE['cart']));
	return $cart;
}`, true},

	// --- wp-missing-authz (built in) ---
	{"wp-missing-authz", "nopriv ajax updates an option", "plugin.php", `<?php
add_action('wp_ajax_nopriv_mp_save', 'mp_save');
add_action('wp_ajax_mp_save', 'mp_save');
function mp_save() {
	update_option('mp_settings', $_POST['settings']);
	wp_send_json_success();
}`, true},
	{"wp-missing-authz", "ajax with capability check", "plugin.php", `<?php
add_action('wp_ajax_mp_save', array($this, 'mp_save'));
function mp_save() {
	check_ajax_referer('mp_save');
	if (!current_user_can('manage_options')) wp_die();
	update_option('mp_settings', $_POST['settings']);
}`, false},
	{"wp-missing-authz", "ajax that only reads", "plugin.php", `<?php
add_action('wp_ajax_nopriv_mp_list', 'mp_list');
function mp_list() {
	wp_send_json(get_option('mp_public_list'));
}`, false},
	{"wp-missing-authz", "public REST route that deletes", "rest.php", `<?php
register_rest_route('mp/v1', '/item/(?P<id>\d+)', array(
	'methods' => WP_REST_Server::DELETABLE,
	'callback' => 'mp_delete_item',
	'permission_callback' => '__return_true',
));`, true},
	// --- false positives seen on real MCP repos ---
	{"tool-path-to-fs", "input is the data written, not the path", "agent_bridge.py", `
@app.post("/save")
def save(request: SaveRequest):
    p = Path(DATA_DIR) / "latest.json"
    p.write_text(request.content)
`, false},
	{"tool-path-to-fs", "receiver path built from input", "agent_bridge.py", `
@app.post("/save")
def save(name: str, content: str):
    p = Path(DATA_DIR) / name
    p.write_text(content)
`, true},
	{"tool-path-to-fs", "helper with a payload param", "store.py", `
def persist(payload):
    with open(tmp_path, "w") as f:
        json.dump(payload, f)
`, false},
	{"tool-path-to-fs", "build script reading argv", "scripts/build.py", `
@app.get("/x")
def x(name):
    open(name).read()
`, false},
	{"fetch-from-input", "fixed host, input only in the path", "route.ts", `
export async function GET(req: NextRequest) {
  const upstream = await fetch(` + "`${GATEWAY_URL}/agent/stream${req.nextUrl.search}`" + `);
  return upstream;
}`, false},
	{"fetch-from-input", "client code passing a body", "api.ts", `
export async function createMeeting(body) {
  return fetch("/api/meetings", { method: "POST", body: JSON.stringify(body) });
}`, false},
	{"fetch-from-input", "go outbound retry helper", "client.go", `
func retry(ctx context.Context, req *http.Request) (*http.Response, error) {
	r2, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), nil)
	return http.DefaultClient.Do(r2)
}`, false},
	{"shell-from-input", "method named exec is not a call", "adb.ts", `
class Adb {
  async exec(...args: string[]): Promise<string> {
    return run("adb", args);
  }
}`, false},
	{"tool-path-to-fs", "promise .then callback after a client get", "client.ts", `
function load() {
  api.get('/files').then((list) => {
    fs.writeFileSync(list.path, "x");
  });
}`, false},

	{"tool-path-to-fs", "multer temp path is server-set", "routes.js", `
router.post('/avatar', upload.single('file'), async (req, res) => {
  const clean = sanitize(await fsp.readFile(req.file.path, 'utf8'));
  await fsp.rm(req.file.path, { force: true });
});`, false},
	{"tool-path-to-fs", "original filename from the client still counts", "routes.js", `
router.post('/avatar', upload.single('file'), async (req, res) => {
  await fsp.writeFile(path.join(UPLOADS, req.body.name), data);
});`, true},
}

func TestCheckers(t *testing.T) {
	checkers, errs := loadCheckers(t.TempDir())
	if len(errs) > 0 {
		t.Fatalf("checker load errors: %+v", errs)
	}
	ids := map[string]bool{}
	for _, c := range checkers {
		ids[c.ID] = true
	}
	for _, c := range checkerCases {
		if !ids[c.checker] && c.checker != wpAuthzChecker {
			t.Fatalf("no checker %q", c.checker)
		}
		got := false
		var lines []int
		for _, f := range runCheckers(c.file, []byte(c.src), checkers) {
			if f.Checker == c.checker {
				got = true
				lines = append(lines, f.Line)
			}
		}
		if got != c.want {
			t.Errorf("%s / %s: fired=%v (lines %v), want %v", c.checker, c.name, got, lines, c.want)
		}
	}
}

func TestCheckersIgnoreUnknownLanguages(t *testing.T) {
	checkers, _ := loadCheckers(t.TempDir())
	if f := runCheckers("README.md", []byte("eval(x)"), checkers); f != nil {
		t.Errorf("markdown produced findings: %+v", f)
	}
}
