package main

// Fixtures for the checkers added from the bench (plan 17): library mode, open redirect,
// template injection, prototype pollution and routes missing their siblings' auth. Shapes
// follow real advisories in the bench; each vulnerable case has a fixed twin.

func init() {
	checkerCases = append(checkerCases, []struct {
		checker, name, file, src string
		want                     bool
	}{
		// --- library mode: an exported function's arguments are the input ---
		{"shell-from-input", "exported js function runs its argument through a shell", "index.js", `
const { execSync } = require("child_process");
function gitDiff(a, b) {
  return execSync("git diff " + a + " " + b).toString();
}
module.exports = { gitDiff };`, true},
		{"shell-from-input", "same function, not exported", "index.js", `
const { execSync } = require("child_process");
function gitDiff(a, b) {
  return execSync("git diff " + a + " " + b).toString();
}
console.log(gitDiff("HEAD~1", "HEAD"));`, false},
		{"shell-from-input", "exported function switched to an argument array", "index.js", `
const { execFileSync } = require("child_process");
export function gitDiff(a, b) {
  return execFileSync("git", ["diff", a, b]).toString();
}`, false},
		{"tool-path-to-fs", "public python method writes to a caller's path", "pkg/store.py", `
class Store:
    def save(self, name: str, data: bytes):
        with open(os.path.join(self.root, name), "wb") as f:
            f.write(data)
`, true},
		{"tool-path-to-fs", "private python helper is not API", "pkg/store.py", `
class Store:
    def _save(self, name: str, data: bytes):
        with open(os.path.join(self.root, name), "wb") as f:
            f.write(data)
`, false},
		{"tool-path-to-fs", "numeric parameter can't carry a path", "pkg/store.py", `
def load_page(page: int):
    with open(f"pages/{page}.json") as f:
        return f.read()
`, false},

		// --- open redirect ---
		{"redirect-from-input", "express redirect to a query parameter", "server.js", `
app.get("/go", (req, res) => {
  res.redirect(req.query.next);
});`, true},
		{"redirect-from-input", "express redirect with a status to a query parameter", "server.js", `
app.get("/go", (req, res) => {
  res.redirect(302, req.query.next);
});`, true},
		{"redirect-from-input", "input only fills the query of a local path", "server.js", `
app.get("/go", (req, res) => {
  res.redirect("/account?tab=" + req.query.tab);
});`, false},
		{"redirect-from-input", "flask redirect to next", "views.py", `
from flask import Flask, redirect, request

@app.route("/login", methods=["POST"])
def login():
    return redirect(request.args.get("next"))
`, true},
		// shapes from reviewing the first real run with these checkers
		{"redirect-from-input", "the app's own redirect helper, not the framework's", "routes/accounts.py", `
from ..web import redirect

@router.post("/accounts/{aid}")
async def save(request: Request, aid: str):
    values = await request.form()
    return redirect(values["return_to"], "Saved.")
`, false},
		{"redirect-from-input", "a fixed table picks the target", "routes/settings.py", `
from fastapi.responses import RedirectResponse

@router.get("/settings/old")
async def moved_page(request: Request):
    return RedirectResponse(MOVED[request.query_params["section"]])
`, false},
		{"redirect-from-input", "back to the current page", "web.py", `
from fastapi.responses import RedirectResponse

@app.post("/period")
async def set_period(request: Request):
    return RedirectResponse(f"{request.url.path}?{urlencode(dict(request.query_params))}", status_code=303)
`, false},
		{"tool-path-to-fs", "wrapper that checks the id against a compiled pattern", "process_api.py", `
_RUN_ID = re.compile(r"[a-f0-9]{32}")

def _read_run(run_id: str) -> dict:
    if not _RUN_ID.fullmatch(run_id):
        raise HTTPException(404)
    return json.loads((RUNS / f"{run_id}.json").read_text())

@router.get("/runs/{run_id}")
def read_run(run_id: str):
    return _read_run(run_id)
`, false},
		{"tool-path-to-fs", "name checked against a fixed set", "dashboard.py", `
@router.get("/samples/{name}")
async def sample_file(request: Request, name: str):
    if name not in FILES:
        return redirect("/")
    return FileResponse(SAMPLES / name)
`, false},
		{routeAuthChecker, "api client calls are not routes", "services/apikeys/index.ts", `
export const list = (params) => request.get("/apikeys", { params });
export const create = (body) => request.post("/apikeys", body, { auth: true });
export const remove = (id) => request.delete("/apikeys/" + id, { auth: true });
export const rotate = (id) => request.post("/apikeys/rotate", { id, auth: true });`, false},
		{routeAuthChecker, "an auth router's public routes are on purpose", "dashboard/routes_auth.py", `
@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user

@router.post("/logout")
def logout(user: User = Depends(get_current_user)):
    return end(user)

@router.post("/password")
def password(body: Pw, user: User = Depends(get_current_user)):
    return change(user, body)

@router.post("/handoff/redeem")
def redeem(code: str):
    return exchange(code)
`, false},
		{"tool-path-to-fs", "a pydantic model named FileResponse", "routes/drive.py", `
def _file_to_response(file: DriveFile, include_content: bool = False) -> FileResponse:
    return FileResponse(file_id=file.file_id, name=file.name, content=file.content if include_content else None)

@router.get("/file/{file_id}", response_model=FileResponse)
async def get_file(file_id: str):
    return _file_to_response(service.get_file(file_id))
`, false},
		{"redirect-from-input", "http to https on the same host", "middleware/autocert.go", `
func redirectTLS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}`, false},
		{"redirect-from-input", "go handler redirects to a query parameter", "auth.go", `
func callback(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}`, true},
		{"redirect-from-input", "django checks the host first", "views.py", `
def login(request):
    nxt = request.GET.get("next")
    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        nxt = "/"
    return HttpResponseRedirect(nxt)
`, false},

		// --- template injection ---
		{"template-from-input", "jinja template built from tool input", "server.py", `
@mcp.tool()
def render(template: str, name: str):
    return Template(template).render(name=name)
`, true},
		{"template-from-input", "input only fills a fixed template", "server.py", `
@mcp.tool()
def greet(name: str):
    return Template("Hello {{ name }}").render(name=name)
`, false},
		{"template-from-input", "sandboxed environment", "server.py", `
@app.post("/prompts/test")
def test_prompt(template: str):
    env = ImmutableSandboxedEnvironment()
    return env.from_string(template).render()
`, false},
		{"template-from-input", "ejs renders a template from the body", "server.js", `
app.post("/preview", (req, res) => {
  res.send(ejs.render(req.body.template, { user: req.user }));
});`, true},

		// --- prototype pollution ---
		{"proto-pollution", "exported setter walks a dotted path", "src/set.js", `
export function setPath(obj, path, value) {
  const parts = path.split(".");
  let cur = obj;
  for (const p of parts.slice(0, -1)) {
    cur = cur[p] = cur[p] || {};
  }
  cur[parts[parts.length - 1]] = value;
}`, true},
		{"proto-pollution", "setter refuses __proto__", "src/set.js", `
export function setPath(obj, path, value) {
  const parts = path.split(".");
  if (parts.includes("__proto__") || parts.includes("constructor")) throw new Error("bad key");
  let cur = obj;
  for (const p of parts.slice(0, -1)) {
    cur = cur[p] = cur[p] || {};
  }
  cur[parts[parts.length - 1]] = value;
}`, false},
		{"proto-pollution", "exported recursive merge", "src/merge.js", `
export function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      target[key] = target[key] || {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}`, true},
		{"proto-pollution", "flat copy of the body only touches one object", "server.js", `
app.post("/settings", (req, res) => {
  for (const key in req.body) {
    settings[key] = req.body[key];
  }
  res.json(settings);
});`, false},

		// --- routes missing their siblings' auth ---
		{routeAuthChecker, "express route without the middleware its siblings use", "routes/admin.js", `
router.get("/users", requireAuth, listUsers);
router.post("/users", requireAuth, createUser);
router.delete("/users/:id", requireAuth, deleteUser);
router.post("/settings", saveSettings);
router.get("/health", health);`, true},
		{routeAuthChecker, "every write route has it", "routes/admin.js", `
router.get("/users", requireAuth, listUsers);
router.post("/users", requireAuth, createUser);
router.delete("/users/:id", requireAuth, deleteUser);
router.get("/health", health);`, false},
		{routeAuthChecker, "router-wide auth covers everything", "routes/admin.js", `
router.use(requireAuth);
router.get("/users", listUsers);
router.post("/users", createUser);
router.post("/settings", saveSettings);`, false},
		{routeAuthChecker, "fastapi route without the dependency its siblings take", "api/admin.py", `
@router.get("/users")
def list_users(user: User = Depends(get_current_user)):
    return db.users()

@router.post("/users")
def create_user(body: NewUser, user: User = Depends(get_current_user)):
    return db.add(body)

@router.delete("/users/{uid}")
def delete_user(uid: str, user: User = Depends(get_current_user)):
    return db.remove(uid)

@router.post("/backup/restore")
def restore(path: str):
    return backups.restore(path)
`, true},
		{routeAuthChecker, "a file with no auth anywhere says nothing", "api/public.py", `
@router.get("/items")
def items():
    return db.items()

@router.post("/items")
def add(item: Item):
    return db.add(item)

@router.delete("/items/{i}")
def remove(i: str):
    return db.remove(i)
`, false},
	}...)
}
