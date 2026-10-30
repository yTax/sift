"use strict";

// Library: the dork, checker, sink and Semgrep files sift runs with. Built-in files ship inside
// sift; saving one writes your own copy to the folder of the same name, which replaces it.

const KINDS = {
  dorks: { title: "Scenes (dorks)", one: "scene", help: "Where to look: GitHub searches, WordPress or Jenkins plugin lists." },
  checkers: { title: "Checkers", one: "checker", help: "What to look for: input reaching a dangerous call in one function." },
  sinks: { title: "Sink profiles", one: "sink profile", help: "Per-language patterns the scan counts to rank repos (inputs, sinks, auth code)." },
  semgrep: { title: "Semgrep rules", one: "rule file", help: "Taint rules that confirm checker findings on the top repos. metadata.class must match a checker class." },
};

const CHECKER_LANGS = { "js-ts": "sample.ts", python: "sample.py", go: "sample.go", php: "sample.php" };

const TEMPLATES = {
  dorks: { data: { name: "", description: "", source: "github", base: "archived:false pushed:>{{since}}", max_results_per_query: 300, queries: [{ id: "q1", q: "" }] } },
  checkers: { data: { id: "", class: "", weight: 2, message: "", langs: { python: { sinks: [] } } } },
  sinks: {
    text: `id: my-lang
name: My language
extensions: [.ext]
skip_paths: []

# each pattern is a Go regex matched line by line; weight 3 = exec/deserialization, 2 = path/SSRF/SQLi, 1 = noisy
surface:
  - { pattern: 'route\\(', label: route }
sinks:
  - { pattern: '\\bexec\\(', label: shell command, class: cmd-exec, weight: 3 }
auth:
  - { pattern: 'authorize\\b', label: auth check }
`,
  },
  semgrep: {
    text: `rules:
  - id: my.rule.python
    languages: [python]
    severity: ERROR
    message: Input reaches eval
    metadata: { class: code-exec }   # must match a checker class to confirm its findings
    mode: taint
    pattern-sources:
      - pattern: request.$ATTR
    pattern-sinks:
      - pattern: eval(...)
`,
  },
};

const lib = { items: null, ed: null };

// fillView is replaceChildren with h()'s handling of kids: arrays flatten, null and false drop out.
function fillView(el, ...kids) {
  el.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false));
}

async function loadLibrary() {
  lib.items = await api("/api/library");
}

function libItem(kind, name) {
  return ((lib.items || {})[kind] || []).find((i) => i.name === name);
}

// ---------- list ----------

async function openLibrary() {
  const view = document.getElementById("library-view");
  try {
    await loadLibrary();
  } catch (err) {
    fillView(view, h("p", null, err.message));
    return;
  }
  const base = state.info ? state.info.base : "";
  fillView(view, 
    h("p", { class: "muted" }, "Built-in files ship with sift and update with it. Saving one makes your own copy in ",
      h("span", { class: "mono" }, base + "/<kind>/"), ", which replaces it until you reset it. You can also drop .yaml files into those folders by hand."),
    Object.entries(KINDS).map(([kind, k]) => h("section", { class: "card" },
      h("div", { class: "libhead" },
        h("h2", null, k.title),
        h("a", { class: "btn", href: "#lib-new=" + kind }, "New " + k.one)),
      h("p", { class: "muted" }, k.help),
      h("ul", { class: "plain" }, (lib.items[kind] || []).map((it) => libRow(kind, it))))));
}

function libRow(kind, it) {
  const toggle = h("input", { type: "checkbox", title: "Use this file in runs" });
  toggle.checked = it.enabled;
  toggle.addEventListener("change", async () => {
    try {
      if (kind === "dorks") await api("/api/category", { id: it.id, field: "enabled", value: toggle.checked });
      else await api("/api/library/toggle", { kind, name: it.name, enabled: toggle.checked });
      it.enabled = toggle.checked;
      if (kind === "dorks") loadState();
    } catch (err) { toggle.checked = !toggle.checked; alertLine(err.message); }
  });
  return h("li", { class: "librow" },
    toggle,
    h("a", { href: "#lib=" + kind + "/" + encodeURIComponent(it.name) },
      h("span", { class: "name" }, it.title), " ",
      h("span", { class: "chip" + (it.origin === "built-in" ? "" : " good") }, it.origin), " ",
      it.error ? h("span", { class: "chip bad" }, "error") : null,
      h("div", { class: "desc" }, it.description)));
}

// ---------- editor ----------

async function openLibEditor(kind, name) {
  if (!KINDS[kind]) { location.hash = "#library"; return; }
  if (!lib.items) {
    try { await loadLibrary(); } catch (err) { alertLine(err.message); return; }
  }
  const builder = kind === "dorks" || kind === "checkers";
  let ed;
  if (name == null) {
    const t = TEMPLATES[kind];
    ed = { kind, name: "", origin: "new", isNew: true, mode: t.data ? "form" : "yaml",
      data: t.data ? structuredClone(t.data) : null, text: t.text || "" };
  } else {
    const it = libItem(kind, name);
    if (!it) { document.getElementById("library-view").replaceChildren(h("p", null, "No such file. ", h("a", { href: "#library" }, "Back"))); return; }
    ed = { kind, name, origin: it.origin, isNew: false, mode: builder && it.data && !it.error ? "form" : "yaml",
      data: it.data ? structuredClone(it.data) : {}, text: it.text, id: it.id };
  }
  lib.ed = ed;
  renderEditor();
}

function renderEditor() {
  const ed = lib.ed;
  const k = KINDS[ed.kind];
  const builder = ed.kind === "dorks" || ed.kind === "checkers";
  const view = document.getElementById("library-view");
  const status = h("span", { class: "muted" });
  const nameIn = h("input", { type: "text", placeholder: "file name, e.g. my-" + ed.kind.replace(/s$/, ""), spellcheck: "false" });
  nameIn.value = ed.name;
  nameIn.disabled = !ed.isNew;
  nameIn.addEventListener("input", () => { ed.name = nameIn.value; });

  const body = h("div");
  const fill = () => fillView(body, ed.mode === "form" ? (ed.kind === "dorks" ? dorkForm(ed) : checkerForm(ed)) : yamlBox(ed));
  const modeBtn = (mode, label) => h("button", { class: "btn" + (ed.mode === mode ? " on" : ""), onclick: async () => {
    if (ed.mode === mode) return;
    try {
      if (mode === "yaml") ed.text = (await api("/api/library/convert", { data: ed.data })).text;
      else ed.data = (await api("/api/library/convert", { text: ed.text })).data || {};
      ed.mode = mode;
      renderEditor();
    } catch (err) { status.textContent = err.message; }
  } }, label);

  const save = async () => {
    status.textContent = "saving…";
    try {
      const text = ed.mode === "form" ? (await api("/api/library/convert", { data: ed.data })).text : ed.text;
      let name = ed.name.trim();
      if (!name) name = (ed.data && (ed.data.id || ed.data.name)) || "";
      const res = await api("/api/library/save", { kind: ed.kind, name, text });
      await loadLibrary();
      loadState();
      status.textContent = "saved as " + ed.kind + "/" + res.name;
      if (ed.isNew || res.name !== ed.name) location.hash = "#lib=" + ed.kind + "/" + encodeURIComponent(res.name);
      else { ed.origin = libItem(ed.kind, res.name).origin; }
    } catch (err) { status.textContent = err.message; }
  };

  let armed = false;
  const removeBtn = ed.origin === "edited" || ed.origin === "yours" ? h("button", { class: "btn dud", onclick: async (e) => {
    if (!armed) { armed = true; e.target.textContent = "Click again to confirm"; return; }
    try {
      await api("/api/library/remove", { kind: ed.kind, name: ed.name });
      await loadLibrary();
      loadState();
      location.hash = ed.origin === "edited" ? "#lib=" + ed.kind + "/" + encodeURIComponent(ed.name) : "#library";
      if (ed.origin === "edited") openLibEditor(ed.kind, ed.name);
    } catch (err) { status.textContent = err.message; }
  } }, ed.origin === "edited" ? "Reset to built-in" : "Delete") : null;

  fillView(view, 
    h("a", { class: "back", href: "#library" }, "← library"),
    h("div", { class: "libhead" },
      h("h1", { class: "edtitle" }, ed.isNew ? "New " + k.one : (ed.data && ed.data.name) || ed.name),
      h("span", { class: "chip" + (ed.origin === "built-in" ? "" : " good") }, ed.origin)),
    h("div", { class: "runform" },
      h("label", null, "File ", nameIn),
      builder ? [modeBtn("form", "Builder"), modeBtn("yaml", "YAML")] : null),
    ed.mode === "form" && ed.origin !== "new" && ed.origin !== "yours"
      ? h("p", { class: "muted" }, "Saving from the builder rewrites the file without its comments. Switch to YAML to keep them.") : null,
    body,
    ed.kind !== "dorks" ? sampleTest(ed) : null,
    h("div", { class: "actions sticky" },
      h("button", { class: "btn primary", onclick: save }, ed.origin === "built-in" ? "Save my copy" : "Save"),
      removeBtn, status));
  fill();
}

function yamlBox(ed) {
  const ta = h("textarea", { class: "yaml", spellcheck: "false" });
  ta.value = ed.text;
  ta.addEventListener("input", () => { ed.text = ta.value; });
  return h("section", { class: "card" }, ta);
}

// ---------- form helpers (they edit ed.data in place; an empty field drops its key) ----------

function setKey(obj, key, v) {
  if (v === "" || v == null || (Array.isArray(v) && !v.length)) delete obj[key];
  else obj[key] = v;
}

function field(label, input, hint) {
  return h("label", { class: "field" }, h("span", null, label), input, hint ? h("small", { class: "muted" }, hint) : null);
}

function textIn(obj, key, placeholder, mono) {
  const el = h("input", { type: "text", placeholder: placeholder || "", spellcheck: "false", class: mono ? "mono" : null });
  el.value = obj[key] ?? "";
  el.addEventListener("input", () => setKey(obj, key, el.value));
  return el;
}

function numIn(obj, key, placeholder) {
  const el = h("input", { type: "number", placeholder: placeholder || "", step: "any" });
  el.value = obj[key] ?? "";
  el.addEventListener("input", () => setKey(obj, key, el.value === "" ? "" : Number(el.value)));
  return el;
}

function checkIn(obj, key, label) {
  const el = h("input", { type: "checkbox" });
  el.checked = !!obj[key];
  el.addEventListener("change", () => setKey(obj, key, el.checked || ""));
  return h("label", { class: "chk" }, el, " " + label);
}

function linesIn(obj, key, placeholder) {
  const el = h("textarea", { class: "mono lines", placeholder: placeholder || "", spellcheck: "false" });
  el.value = (obj[key] || []).join("\n");
  el.addEventListener("input", () => setKey(obj, key, el.value.split("\n").map((s) => s.trim()).filter(Boolean)));
  return el;
}

function selectIn(obj, key, options, onchange) {
  const el = h("select", null, options.map(([v, l]) => h("option", { value: v }, l)));
  el.value = obj[key] ?? "";
  el.addEventListener("change", () => { setKey(obj, key, el.value); if (onchange) onchange(); });
  return el;
}

// ---------- dork builder ----------

function dorkForm(ed) {
  const d = ed.data;
  d.queries = d.queries || [];
  const src = d.source || "github";
  const profiles = (lib.items.sinks || []).map((p) => p.id);
  const sinkBoxes = h("div", { class: "chips" }, profiles.map((id) => {
    const el = h("input", { type: "checkbox" });
    el.checked = (d.sinks || []).includes(id);
    el.addEventListener("change", () => {
      const set = new Set(d.sinks || []);
      if (el.checked) set.add(id); else set.delete(id);
      setKey(d, "sinks", [...set]);
    });
    return h("label", { class: "chk" }, el, " " + id);
  }));
  d.contacts = d.contacts || {};
  const sub = (k) => (d[k] = d[k] || {});
  const queries = h("div");
  const drawQueries = () => queries.replaceChildren(...d.queries.map((q, i) => queryRow(ed, q, i, drawQueries)),
    h("button", { class: "btn", onclick: () => { d.queries.push({ id: "q" + (d.queries.length + 1) }); drawQueries(); } }, "Add query"));
  drawQueries();
  return h("section", { class: "card form" },
    field("Name", textIn(d, "name", "WordPress forms")),
    field("Description", textIn(d, "description", "What lives here and why it's worth hunting")),
    field("Source", selectIn(d, "source", [["github", "GitHub repo search"], ["wordpress", "WordPress plugins"], ["jenkins", "Jenkins plugins"]],
      () => renderEditor())),
    src === "github" ? [
      field("Added to every query", textIn(d, "base", "archived:false pushed:>{{since}}", true),
        "{{since}} = today minus 'max days since push' (Settings); {{days_ago:N}} = N days ago. Forks are excluded already."),
      field("Results per query", numIn(d, "max_results_per_query", "300"),
        "GitHub stops at 1000. Put stars:A..B in a query and set this above 1000 to have sift split it."),
    ] : null,
    src === "wordpress" ? h("div", { class: "row3" },
      field("Min installs", numIn(sub("wordpress"), "min_installs", "1000")),
      field("Max installs", numIn(sub("wordpress"), "max_installs", "300000")),
      field("Max days since update", numIn(sub("wordpress"), "max_days_since_update", "180"))) : null,
    src === "jenkins" ? h("div", { class: "row3" },
      field("Min installs", numIn(sub("jenkins"), "min_popularity", "500")),
      field("Max installs", numIn(sub("jenkins"), "max_popularity", "150000")),
      field("Max days since release", numIn(sub("jenkins"), "max_days_since_release", "365"))) : null,
    field("Sink profiles to grep with", sinkBoxes, "None ticked = all of them."),
    h("div", { class: "chips" },
      checkIn(d.contacts, "discover", "look for a private contact"),
      checkIn(d.contacts, "require", "drop repos without one")),
    h("h2", null, "Queries"),
    queries);
}

function queryRow(ed, q, i, redraw) {
  const d = ed.data;
  const src = d.source || "github";
  const out = h("div", { class: "muted qout" });
  const test = async () => {
    out.textContent = "searching…";
    try {
      const text = (await api("/api/library/convert", { data: d })).text;
      const r = await api("/api/library/test", { kind: "dorks", text, query: q.id });
      fillView(out, 
        h("div", null, h("strong", null, (r.total ?? 0).toLocaleString() + " results"), r.query ? h("span", { class: "mono" }, "  " + r.query) : null),
        r.note ? h("div", null, r.note) : null,
        (r.sample || []).length ? h("div", null, "e.g. " + r.sample.join(", ")) : null);
    } catch (err) { out.textContent = err.message; }
  };
  let main;
  if (src === "github") {
    main = field("Search", textIn(q, "q", "topic:mcp-server language:Python stars:20..3000", true));
  } else if (src === "wordpress") {
    const kind = ["search", "tag", "author", "browse"].find((k) => q[k]) || "tag";
    const val = h("input", { type: "text", placeholder: kind === "browse" ? "popular | updated | new" : "" });
    val.value = q[kind] || "";
    const sel = h("select", null, ["search", "tag", "author", "browse"].map((k) => h("option", { value: k }, k)));
    sel.value = kind;
    const sync = () => { for (const k of ["search", "tag", "author", "browse"]) delete q[k]; setKey(q, sel.value, val.value.trim()); };
    sel.addEventListener("change", sync);
    val.addEventListener("input", sync);
    main = h("div", { class: "row3" }, field("By", sel), field("Value", val), field("Pages", numIn(q, "pages", "3")));
  } else {
    main = h("div", { class: "row3" },
      field("Label", textIn(q, "label", "security")),
      field("Name regex", textIn(q, "name_regex", "(?i)oauth|ldap", true)),
      h("div", null, checkIn(q, "all", "every plugin")));
  }
  return h("div", { class: "qrow" },
    h("div", { class: "row3" },
      field("Id", textIn(q, "id", "q" + (i + 1))),
      field("Note", textIn(q, "note", "why this query exists"))),
    main,
    h("div", { class: "actions" },
      h("button", { class: "btn", onclick: test }, "Test"),
      h("button", { class: "btn", onclick: () => { d.queries.splice(i, 1); redraw(); } }, "Remove")),
    out);
}

// ---------- checker builder ----------

function checkerForm(ed) {
  const d = ed.data;
  d.langs = d.langs || {};
  const classes = [...new Set((lib.items.checkers || []).map((c) => c.data && c.data.class).filter(Boolean))];
  const classIn = textIn(d, "class", "cmd-exec", true);
  classIn.setAttribute("list", "checker-classes");
  return h("section", { class: "card form" },
    h("datalist", { id: "checker-classes" }, classes.map((c) => h("option", { value: c }))),
    h("div", { class: "row3" },
      field("Id", textIn(d, "id", "my-checker", true)),
      field("Bug class", classIn, "Findings group by it; Semgrep confirms by it."),
      field("Weight", numIn(d, "weight", "2"), "3 = code exec, 2 = path/SSRF/SQLi, 1 = low impact")),
    field("Message", textIn(d, "message", "Handler input reaches … with no …")),
    h("p", { class: "muted" }, "A finding is: inside one function that takes request or tool input, a line matching a sink, with the input (or a variable built from it) in that call, and no guard earlier in the function. Patterns are Go regexes, one per line."),
    Object.keys(CHECKER_LANGS).map((lang) => langBlock(d, lang)));
}

function langBlock(d, lang) {
  const on = !!d.langs[lang];
  const box = h("input", { type: "checkbox" });
  box.checked = on;
  box.addEventListener("change", () => {
    if (box.checked) d.langs[lang] = d.langs[lang] || { sinks: [] };
    else delete d.langs[lang];
    renderEditor();
  });
  const l = d.langs[lang];
  return h("details", { class: "lang", open: on },
    h("summary", null, h("label", { class: "chk", onclick: (e) => e.stopPropagation() }, box, " " + lang)),
    l ? [
      field("Sinks", linesIn(l, "sinks", "(^|[^.\\w])exec\\("), "The dangerous call. Name a group (?P<arg>…) to say where the input must appear."),
      h("div", { class: "row3" },
        field("Where the input must be", selectIn(l, "arg", [["", "anywhere in the call"], ["first", "first argument"], ["url-start", "the URL's scheme + host"]])),
        h("div", null, checkIn(l, "interpolated", "only input pasted into a string")),
        h("div", null, checkIn(l, "no_input", "the line alone is the bug"))),
      field("Guards", linesIn(l, "guards", "allowlist|isPrivate"), "Any of these earlier in the function silences it."),
      field("Line guards", linesIn(l, "line_guards", "escapeshellarg\\("), "Only silences when on the sink line itself."),
      field("Requires", linesIn(l, "requires", ""), "The function must also contain one of these."),
    ] : null);
}

// ---------- sample test (checkers, sinks, semgrep) ----------

function sampleTest(ed) {
  const firstLang = ed.data && ed.data.langs ? Object.keys(ed.data.langs)[0] : null;
  const file = h("input", { type: "text", spellcheck: "false", class: "mono" });
  file.value = ed.sampleFile || CHECKER_LANGS[firstLang] || "sample.py";
  file.addEventListener("input", () => { ed.sampleFile = file.value; });
  const code = h("textarea", { class: "mono yaml short", spellcheck: "false", placeholder: "Paste code that should (or shouldn't) be flagged" });
  code.value = ed.sample || "";
  code.addEventListener("input", () => { ed.sample = code.value; });
  const out = h("div");
  const run = async () => {
    fillView(out, h("p", { class: "muted" }, ed.kind === "semgrep" ? "running Semgrep…" : "testing…"));
    try {
      const text = ed.mode === "form" ? (await api("/api/library/convert", { data: ed.data })).text : ed.text;
      const r = await api("/api/library/test", { kind: ed.kind, text, file: file.value, code: code.value });
      fillView(out, sampleResult(ed.kind, r));
    } catch (err) { fillView(out, h("p", { class: "reasons" }, err.message)); }
  };
  return h("section", { class: "card" },
    h("h2", null, "Try it on a sample"),
    h("div", { class: "runform" }, h("label", null, "File name ", file), h("button", { class: "btn", onclick: run }, "Test")),
    h("p", { class: "muted" }, "The extension picks the language. Nothing in the sample runs."),
    code, out);
}

function sampleResult(kind, r) {
  const line = (n, chips, text) => h("li", null, h("span", { class: "mono" }, "L" + n), " ", chips, h("div", { class: "snip" }, text));
  if (kind === "checkers") {
    const fs = r.findings || [];
    return [
      r.note ? h("p", { class: "muted" }, r.note) : null,
      h("p", null, h("strong", null, fs.length + " finding" + (fs.length === 1 ? "" : "s"))),
      h("ul", { class: "plain" }, fs.map((f) => line(f.line,
        [h("span", { class: "chip " + (f.confidence === "high" ? "bad" : "warn") }, f.confidence), f.via ? h("span", { class: "muted" }, " via " + f.via + " ") : null],
        f.snippet))),
      (r.sinks || []).length ? [h("p", { class: "muted" }, "Lines your patterns matched (a sink with no finding means no input reached it, or a guard stopped it):"),
        h("ul", { class: "plain" }, r.sinks.map((x) => line(x.line, h("span", { class: "chip" + (x.kind === "sink" ? " warn" : "") }, x.kind), x.text)))] : null,
    ];
  }
  if (kind === "sinks") {
    const hits = r.hits || [];
    return [h("p", null, h("strong", null, hits.length + " match" + (hits.length === 1 ? "" : "es"))),
      h("ul", { class: "plain" }, hits.map((x) => line(x.line, [h("span", { class: "chip" }, x.kind), " " + x.label + " "], x.text)))];
  }
  const res = r.results || [];
  return [h("p", null, h("strong", null, res.length + " result" + (res.length === 1 ? "" : "s"))),
    h("ul", { class: "plain" }, res.map((x) => line(x.line, [h("span", { class: "chip" }, x.class || "no class"), " " + x.rule], "")))];
}
