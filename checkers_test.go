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
	{"tool-path-to-fs", "flask int converter", "routes.py", `
@api_bp.route('/mailboxes/<address>/messages/<int:msg_id>', methods=['DELETE'])
def delete_message(address, msg_id):
    shutil.rmtree(os.path.join(config.ATTACHMENTS_PATH, str(msg_id)), ignore_errors=True)
`, false},
	{"tool-path-to-fs", "flask string param still counts", "routes.py", `
@api_bp.route('/files/<name>', methods=['DELETE'])
def delete_file(name):
    os.remove(os.path.join(UPLOADS, name))
`, true},
	{"tool-path-to-fs", "fastapi int annotation", "api.py", `
@app.delete("/items/{item_id}")
def delete_item(item_id: int, keep: bool = False):
    shutil.rmtree(os.path.join(DATA, str(item_id)))
`, false},
	{"sql-from-input", "zod number in tool schema", "src/index.ts", `
server.tool("get_row", "Get a row", { id: z.number() }, async ({ id }) => {
  const rows = await db.all(` + "`SELECT * FROM t WHERE id = ${id}`" + `);
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});`, false},
	{"sql-from-input", "zod string in tool schema still counts", "src/index.ts", `
server.tool("find", "Find", { name: z.string() }, async ({ name }) => {
  const rows = await db.all(` + "`SELECT * FROM t WHERE name = '${name}'`" + `);
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});`, true},

	// --- false positives from the second real run (MCP, Minecraft, WordPress, self-hosted) ---
	// a call that closes on its line doesn't borrow the next line's input
	{"code-from-input", "php assert followed by request line", "src/Controller/A.php", `<?php
class A {
    public function patch(Request $request): JsonResponse
    {
        \assert($user instanceof User);
        $data = json_decode($request->getContent(), true);
    }
}`, false},
	{"shell-from-input", "js constant command, input only in options", "routes/ide.js", `
router.post('/git/status', async (req, res) => {
  const statusOutput = execSync('git status --porcelain', {
    cwd: req.pluginPath,
  });
});`, false},
	{"shell-from-input", "js input in the command itself", "routes/ide.js", `
router.post('/git/checkout', async (req, res) => {
  execSync(` + "`git checkout ${req.body.branch}`" + `, {
    cwd: dir,
  });
});`, true},
	{"sql-from-input", "js prepare with the input bound in get()", "routes/admin.js", `
router.get('/:id', (req, res) => {
  const target = db.prepare('SELECT email FROM users WHERE id = ?').get(req.params.id);
  res.json(target);
});`, false},
	{"sql-from-input", "python bound params on the next line", "app/main.py", `
@app.post("/feedback")
def feedback_message_add(body: dict):
    conn.execute("INSERT INTO feedback_messages (id, body) VALUES (?, ?)",
                 (new_id, body["text"]))
`, false},
	{"sql-from-input", "python concat with commas inside the query string", "app/main.py", `
@app.post("/find")
def find(body: dict):
    conn.execute("SELECT a, b FROM t WHERE x = '" + body["x"] + "'")
`, true},
	// methods that share a name with a dangerous function
	{"code-from-input", "php call_user_func with request as a plain argument", "app/App.php", `<?php
function dispatch($request, $controller, $parameters) {
    return call_user_func($controller, $request, $parameters);
}`, false},
	{"code-from-input", "php call_user_func on a request value", "app/App.php", `<?php
function dispatch() {
    $cb = $_GET['cb'];
    return call_user_func($cb, 1);
}`, true},
	{"shell-from-input", "php method named system", "routes/nodes.php", `<?php
function handle($request, $id) {
    return (new WingsAdminController())->system($request, (int) $id);
}`, false},
	{"shell-from-input", "php system() on request input", "routes/nodes.php", `<?php
function handle() {
    system('ping -c 1 ' . $_GET['host']);
}`, true},
	{"shell-from-input", "php backticks inside a string literal", "bootstrap/app.php", `<?php
function render($request) {
    $lines = ['Nothing lives at :url.', ['url' => '` + "`" + `'.str_replace('` + "`" + `', '%60', $request->url()).'` + "`" + `']];
}`, false},
	{"tool-path-to-fs", "php methods named rename/require/file", "app/WebSpaces.php", `<?php
function rename($request, $uuid) {
    $denied = CheckWebSpacePermission::require($request, $space, $permission);
    $recipe->setPhoto($request->file('photo'));
    return (new WebSpaceFilesController())->rename($request, $uuid);
}`, false},
	{"tool-path-to-fs", "php reading the request body", "api/notes.php", `<?php
function updateColor() {
    $input = json_decode(file_get_contents('php://input'), true);
    return $input['color'];
}`, false},
	{"tool-path-to-fs", "python copyfileobj takes file objects", "routes/upload.py", `
@app.post("/upload")
async def upload_file(file: UploadFile):
    with open(DEST, "wb") as f:
        shutil.copyfileobj(file.file, f)
`, false},
	{"xss-from-input", "drf dict response is JSON", "views.py", `
@app.route("/strava")
def post(code):
    return Response({'message': f'Strava request failed: {code}'}, status=502)
`, false},
	{"xss-from-input", "flask text response with path input", "settings/routes.py", `
@app.route("/settings/<area>")
def settings_area(area):
    return Response(f"unknown settings area {area!r}", status=404)
`, true},
	{"xss-from-input", "empty response before a line with input", "routes.py", `
@app.get("/stream")
def stream(fmt):
    if gone:
        return Response(status_code=499)
    log(f"<b>{fmt}</b>")
`, false},
	{"fetch-from-input", "go request context is not the url", "gateway.go", `
func handleHealth(w http.ResponseWriter, r *http.Request) {
	probe, err := http.NewRequestWithContext(r.Context(), http.MethodGet, collectorHealthURL, nil)
	_ = probe
}`, false},
	{"fetch-from-input", "go url from the query string", "proxy.go", `
func handleProxy(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	_ = req
}`, true},
	{"fetch-from-input", "python url built by a helper on a fixed controller", "tools/tags.py", `
@mcp.tool()
async def update_mac_tag(site_id: str, name: str):
    response = await client.put(_endpoint(site_id), json_data={})
`, false},
	{"fetch-from-input", "python url wrapped in str()", "tools/fetch.py", `
@mcp.tool()
async def fetch_page(url: str):
    response = await client.get(str(url))
`, true},
	{"shell-from-input", "intentionally vulnerable eval fixtures", "evals/vulnerable/x-001/src/server.js", `
server.tool("run", "Run", { file: z.string() }, async ({ file }) => {
  const out = execSync(` + "`wc -l ${file}`" + `).toString();
});`, false},
	// backticks in docblocks, trailing comments and log strings are markdown, not the operator
	{"shell-from-input", "php backticks in a docblock", "utils.php", `<?php
function clean_request() {
	/**
	 * Returns the sanitized version of the ` + "`$_REQUEST`" + ` super-global array.
	 */
	return $_REQUEST;
}`, false},
	{"shell-from-input", "php backticks in a trailing comment", "blocks.php", `<?php
function post_type() {
	$post_type = $_GET['t'] ?? 'post'; // If ` + "`$_GET`" + ` is not set it's a basic post.
}`, false},
	{"shell-from-input", "php backticks in a log string", "notify.php", `<?php
function notify() {
	$log[] = 'Origin (` + "`$_SERVER[\"HTTP_HOST\"]`" + `) validated.';
	$log[] = 'Invalid Order Id: ` + "`' . $_GET['order-id'] . '`" + `';
}`, false},
	{"code-from-input", "python eval in a docstring example", "sdk.py", `
async def run_agent(message: str, tools=None):
    """Run the agent.

    Example:
        @tool
        def calculator(expression: str) -> float:
            return eval(expression)
    """
    return await agent.run(message)
`, false},
	{"code-from-input", "python eval after a docstring", "tools/calc.py", `
@mcp.tool()
def calculator(expression: str) -> float:
    """Evaluate a math expression."""
    return eval(expression)
`, true},
	{"shell-from-input", "js exec in a block comment", "server.js", `
app.post("/run", (req, res) => {
  /*
  exec(req.body.cmd);
  */
  res.send("ok");
});`, false},
	{"shell-from-input", "js exec after a /* route", "server.js", `
app.post("/*", (req, res) => {
  exec(req.body.cmd);
});`, true},
	{"xss-from-input", "php input only compared", "menu.php", `<?php
function panel() {
	echo '<div class="group"' . ((!empty($_GET['open']) && $_GET['open'] === 'pp') ? ' data-open' : '') . '>';
	echo ( isset( $_GET['edit-menu-item'] ) && $item_id == $_GET['edit-menu-item'] ) ? admin_url( 'nav-menus.php' ) : '';
}`, false},
	{"xss-from-input", "php input compared then echoed", "menu.php", `<?php
function panel() {
	echo ( isset( $_GET['tab'] ) && $_GET['tab'] !== '' ) ? '<b>' . $_GET['tab'] . '</b>' : '';
}`, true},
	{"shell-from-input", "php backtick operator", "tools.php", `<?php
function run_ping() {
	$out = ` + "`ping -c 1 $_GET[host]`" + `;
}`, true},
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
