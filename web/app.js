"use strict";

// Everything shown here comes from strangers' repos (names, descriptions, snippets, contacts),
// so text only ever goes in through textContent, and links only through safeURL.

const PAGE = 150;

const PART_LABELS = {
  findings: "Checker findings",
  pairing: "Input + sink in one file",
  sinks: "Dangerous calls",
  surface: "Input entry points",
  auth: "Auth code",
  cve_path: "CVE route",
  history: "Past advisories",
  responsiveness: "Maintainer replies",
  freshness: "Recent pushes",
  contact: "Private contact",
};

const CVE_ROUTES = {
  "github-pvr": ["GitHub private report", "good",
    "Report it privately from the repo's Security tab (Report a vulnerability). The maintainer publishes a GitHub advisory and GitHub assigns the CVE."],
  "github-advisory": ["GitHub advisory", "good",
    "No private reporting button, but they've published GitHub advisories before. Contact them privately and ask them to open one; GitHub assigns the CVE."],
  "security-policy": ["SECURITY.md", "warn",
    "Follow their security policy. Ask them to publish a GitHub advisory so a CVE gets assigned, or request one from MITRE."],
  "wordpress-cna": ["WordPress CNA", "good",
    "Report through Wordfence, Patchstack or WPScan. They contact the vendor and assign the CVE."],
  "jenkins-cna": ["Jenkins CNA", "good",
    "Report to the Jenkins security team (SECURITY project on their Jira). They handle the maintainer and assign the CVE."],
  "mitre": ["MITRE form", "warn",
    "No CNA on the path. Contact the maintainer privately, then request the CVE yourself through MITRE's form."],
  "none": ["no route", "bad", "No private contact found."],
};

const state = { info: null, repos: [], shown: PAGE, detailKey: null, running: false };

// ---------- helpers ----------

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "href") { const u = safeURL(v); if (u) el.href = u; }
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function safeURL(u) {
  if (typeof u !== "string") return null;
  if (u.startsWith("#")) return u;
  return /^(https?:\/\/|mailto:)/i.test(u) ? u : null;
}

function ext(href, ...kids) {
  return h("a", { href, target: "_blank", rel: "noopener noreferrer" }, ...kids);
}

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Sift": "1" },
    body: JSON.stringify(body),
  };
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function ago(iso) {
  if (!iso) return "";
  const d = (Date.now() - new Date(iso).getTime()) / 86400000;
  if (!isFinite(d) || d < 0) return "";
  if (d < 1) return "today";
  if (d < 60) return Math.round(d) + "d ago";
  if (d < 730) return Math.round(d / 30) + "mo ago";
  return Math.round(d / 365) + "y ago";
}

function fmtScore(s) {
  return s ? s.total.toFixed(1) : "–";
}

function routeChip(route) {
  const r = CVE_ROUTES[route];
  if (!r) return null;
  return h("span", { class: "chip " + r[1] }, r[0]);
}

function short(n) {
  return n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + "k" : String(n);
}

// ---------- list ----------

function filtered() {
  const q = document.getElementById("q").value.trim().toLowerCase();
  const scene = document.getElementById("f-scene").value;
  const status = document.getElementById("f-status").value;
  const verdict = document.getElementById("f-verdict").value;
  const all = document.getElementById("f-all").checked;
  const unscanned = document.getElementById("f-unscanned").checked;
  const high = document.getElementById("f-high").checked;
  const confirmedOnly = document.getElementById("f-confirmed").checked;
  const out = state.repos.filter((r) => {
    if (!all && !r.filter.pass) return false;
    if (!unscanned && !r.scanned) return false;
    if (high && !r.high_findings) return false;
    if (confirmedOnly && !r.confirmed) return false;
    if (scene && !(r.categories || []).includes(scene)) return false;
    if (status === "open" ? r.status === "skipped" : status && r.status !== status) return false;
    if (verdict === "none" ? r.verdict : verdict && r.verdict !== verdict) return false;
    if (q) {
      const hay = (r.name + " " + (r.description || "") + " " + (r.language || "") + " " + (r.variant_of || []).join(" ")).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  const sort = document.getElementById("f-sort").value;
  const key = {
    score: (r) => (r.score ? r.score.total : -1),
    paired: (r) => r.paired || 0,
    findings: (r) => (r.confirmed || 0) * 1e9 + (r.high_findings || 0) * 1e6 + (r.findings || 0) * 1000 + (r.score ? r.score.total : 0),
    stars: (r) => r.popularity || 0,
    pushed: (r) => (r.pushed_at ? Date.parse(r.pushed_at) : 0),
  }[sort];
  return out.sort((a, b) => key(b) - key(a));
}

function rowEl(r) {
  const s = r.score;
  return h("a", { class: "row", href: "#repo=" + encodeURIComponent(r.key) },
    h("div", { class: "score" + (s && s.partial ? " partial" : "") }, fmtScore(s)),
    h("div", null,
      h("div", { class: "name" }, r.name),
      r.description ? h("div", { class: "desc" }, r.description) : null),
    h("div", { class: "col-extra chips" },
      routeChip(r.cve_path),
      r.confirmed ? h("span", { class: "chip good" }, r.confirmed + " confirmed") : null,
      r.high_findings ? h("span", { class: "chip bad" }, r.high_findings + " high") : null,
      r.findings ? h("span", { class: "chip warn" }, r.findings + " finding" + (r.findings > 1 ? "s" : "")) : null,
      r.paired ? h("span", { class: "chip" }, r.paired + " paired") : null,
      r.advisories > 0 ? h("span", { class: "chip" }, r.advisories + " GHSA") : null,
      r.sec_issues > 0 ? h("span", { class: "chip warn" }, r.sec_issues + " open security issue" + (r.sec_issues > 1 ? "s" : "")) : null),
    h("div", { class: "col-extra meta" },
      [r.language, r.popularity ? "★" + short(r.popularity) : ""].filter(Boolean).join(" · ")),
    h("div", { class: "col-extra meta" },
      r.verdict ? h("span", { class: "chip " + (r.verdict === "real" ? "good" : "bad") }, r.verdict) : null,
      r.status !== "new" ? " " + r.status : "",
      r.filter.pass ? "" : " filtered"));
}

function renderList() {
  const list = filtered();
  const rows = document.getElementById("rows");
  rows.replaceChildren(...list.slice(0, state.shown).map(rowEl));
  document.getElementById("count").textContent =
    list.length + " of " + state.repos.length + " repos" + (list.length > state.shown ? ", showing " + state.shown : "");
  document.getElementById("more").hidden = list.length <= state.shown;
}

async function loadRepos() {
  state.repos = await api("/api/repos");
  renderList();
}

// ---------- detail ----------

function ghLink(repo, ref, path, line) {
  if (!repo.github_repo) return null;
  return "https://github.com/" + repo.github_repo + "/blob/" + (ref || "HEAD") + "/" +
    path.split("/").map(encodeURIComponent).join("/") + (line ? "#L" + line : "");
}

function partsCard(repo) {
  const s = repo.score;
  if (!s) return null;
  const w = (state.info && state.info.settings.weights) || {};
  const keys = Object.keys(s.parts).sort((a, b) => (w[b] || 0) * s.parts[b] - (w[a] || 0) * s.parts[a]);
  const grid = h("div", { class: "parts" });
  for (const k of keys) {
    const v = s.parts[k];
    const bar = h("div", { class: "pbar" }, h("div"));
    bar.firstChild.style.width = Math.max(0, Math.min(100, v * 10)) + "%";
    grid.append(
      h("div", null, PART_LABELS[k] || k, h("span", { class: "muted" }, " ×" + (w[k] ?? 0))),
      bar,
      h("div", { class: "pval" }, v.toFixed(1)));
  }
  return h("section", { class: "card" }, h("h2", null, "Why it scored " + fmtScore(s) + (s.partial ? " (not scanned yet)" : "")), grid);
}

function reportCard(repo) {
  const route = CVE_ROUTES[repo.cve_path];
  const contacts = (repo.contacts || []).filter((c) => c.kind !== "profile");
  return h("section", { class: "card" },
    h("h2", null, "How to report"),
    route ? h("p", null, routeChip(repo.cve_path), " ", route[2]) : h("p", { class: "muted" }, "Unknown"),
    contacts.length ? h("ul", { class: "plain" }, contacts.map((c) =>
      h("li", null, h("span", { class: "chip" }, c.kind), " ",
        safeURL(c.url) ? ext(c.url, c.value || c.url) : c.value,
        c.where ? h("span", { class: "muted" }, " · " + c.where) : null))) : null);
}

function findingsCard(repo) {
  const sc = repo.scan;
  const list = (sc && sc.findings) || [];
  if (!list.length) return null;
  return h("section", { class: "card" },
    h("h2", null, "Checker findings (" + list.length + "): read these lines first"),
    sc.semgrep ? h("p", { class: "muted" }, sc.semgrep.error ? "Semgrep: " + sc.semgrep.error
      : "Semgrep checked " + sc.semgrep.files + " file(s) " + ago(sc.semgrep.at) + ": " + list.filter((f) => f.confirmed).length + " confirmed.") : null,
    h("p", { class: "muted" }, "Text-level checks, not proof. Each one says which input reached which call; confirm by reading the function."),
    h("ul", { class: "plain" }, list.map((f) => {
      const href = ghLink(repo, sc.ref, f.path, f.line);
      const loc = f.path + ":" + f.line;
      return h("li", null,
        h("div", null,
          f.confirmed ? [h("span", { class: "chip good" }, "confirmed by Semgrep"), " "] : null,
          h("span", { class: "chip " + (f.confidence === "high" ? "bad" : "warn") }, f.confidence), " ",
          h("span", { class: "chip" }, f.class), " ",
          href ? ext(href, h("span", { class: "mono" }, loc)) : h("span", { class: "mono" }, loc),
          f.func ? h("span", { class: "muted" }, " in " + f.func + "()") : null),
        h("div", { class: "muted" }, f.message + (f.via ? " (via " + f.via + ")" : "")),
        h("div", { class: "snip" }, f.snippet));
    })));
}

function hotCard(repo) {
  const sc = repo.scan;
  if (!sc || !(sc.hot_files || []).length) return null;
  return h("section", { class: "card" },
    h("h2", null, "Start reading here (" + sc.paired_files + " files with input and a sink)"),
    h("ul", { class: "plain" }, sc.hot_files.map((f) => {
      const href = ghLink(repo, sc.ref, f.path);
      return h("li", null,
        href ? ext(href, h("span", { class: "mono" }, f.path)) : h("span", { class: "mono" }, f.path),
        " ", h("span", { class: "muted" }, f.weight.toFixed(1)),
        f.near ? h("span", { class: "chip warn" }, "near") : null, " ",
        (f.classes || []).map((c) => h("span", { class: "chip" }, c)));
    })));
}

function hitsCard(repo) {
  const sc = repo.scan;
  if (!sc) return null;
  if (sc.error) return h("section", { class: "card" }, h("h2", null, "Scan"), h("p", { class: "muted" }, sc.error));
  const byFile = new Map();
  for (const hit of sc.hits || []) {
    if (!byFile.has(hit.path)) byFile.set(hit.path, []);
    byFile.get(hit.path).push(hit);
  }
  const hot = new Set((sc.hot_files || []).map((f) => f.path));
  const files = [...byFile.entries()].sort((a, b) =>
    (hot.has(b[0]) - hot.has(a[0])) || b[1].reduce((t, x) => t + x.weight, 0) - a[1].reduce((t, x) => t + x.weight, 0));
  const classes = Object.entries(sc.by_class || {}).sort((a, b) => b[1] - a[1]);
  return h("section", { class: "card" },
    h("h2", null, "Hits by file"),
    h("p", { class: "chips" },
      h("span", { class: "chip" }, sc.sink_hits + " sinks"),
      h("span", { class: "chip" }, sc.surface_hits + " surfaces"),
      h("span", { class: "chip" }, sc.auth_hits + " auth"),
      classes.map(([c, n]) => h("span", { class: "chip" }, c + " " + n)),
      sc.truncated ? h("span", { class: "chip warn" }, "truncated") : null),
    files.slice(0, 60).map(([path, hits]) => h("details", { class: "file" },
      h("summary", null, path, " ", h("span", { class: "muted" }, "(" + hits.length + ")")),
      hits.sort((a, b) => a.line - b.line).map((x) => h("div", { class: "hit" },
        h("div", { class: "ln" }, ghLink(repo, sc.ref, path, x.line) ? ext(ghLink(repo, sc.ref, path, x.line), "L" + x.line) : "L" + x.line),
        h("div", null,
          h("span", { class: "chip" + (x.kind === "sink" ? " bad" : "") }, x.kind), " ", x.label,
          h("div", { class: "snip" }, x.snippet)))))),
    files.length > 60 ? h("p", { class: "muted" }, (files.length - 60) + " more files not shown") : null);
}

function knownCard(repo) {
  const e = repo.enriched || {};
  const adv = e.known_advisories || [];
  const issues = e.security_issues || [];
  if (!adv.length && !issues.length) return null;
  return h("section", { class: "card" },
    h("h2", null, "Already found"),
    issues.length ? [
      h("p", { class: "muted" }, "Open issues that read like security reports. Someone may already be on it:"),
      h("ul", { class: "plain" }, issues.map((i) =>
        h("li", null, safeURL(i.url) ? ext(i.url, i.title) : i.title, h("span", { class: "muted" }, " · " + ago(i.created_at)))))] : null,
    adv.length ? [
      h("p", { class: "muted" }, (e.advisories || adv.length) + " published advisories. Similar bugs often sit next to old ones:"),
      h("ul", { class: "plain" }, adv.map((a) =>
        h("li", null,
          safeURL(a.url) ? ext(a.url, a.cve || a.id) : (a.cve || a.id), " ",
          a.severity ? h("span", { class: "chip" + (a.severity === "critical" || a.severity === "high" ? " bad" : "") }, a.severity) : null, " ",
          (a.cwes || []).map((c) => h("span", { class: "chip" }, c)), " ",
          a.summary, h("span", { class: "muted" }, a.published ? " · " + ago(a.published) : ""))))] : null);
}

function factsCard(repo) {
  const e = repo.enriched || {};
  const rows = [
    ["Popularity", repo.popularity ? repo.popularity + " " + repo.pop_label : ""],
    ["Language", repo.language],
    ["Scenes", (repo.categories || []).join(", ")],
    ["Variant of", (repo.queries || []).filter((q) => q.startsWith("variant-of:")).map((q) => q.slice(11)).join(", ")],
    ["Last push", ago(e.pushed_at)],
    ["Maintainer replied", e.maintainer_last_reply ? ago(e.maintainer_last_reply) : (e.issues_seen ? "not in recent issues" : "")],
    ["Releases / tags", e.releases != null ? e.releases + " / " + e.tags : ""],
    ["Past advisories", e.advisories > 0 ? String(e.advisories) : e.advisories === 0 ? "none" : ""],
    ["Private reporting", e.pvr == null ? "" : e.pvr ? "on" : "off"],
    ["License", e.license],
    ["Scanned", repo.scan && repo.scan.ref ? repo.scan.ref.slice(0, 10) + " · " + repo.scan.files + " files" : ""],
  ].filter(([, v]) => v);
  return h("section", { class: "card" },
    h("h2", null, "Facts"),
    h("dl", { class: "facts" }, rows.map(([k, v]) => [h("dt", null, k), h("dd", null, v)])),
    repo.filter && !repo.filter.pass ? [h("h2", { style: "margin-top:10px" }, "Filtered out because"),
      h("ul", { class: "reasons" }, repo.filter.reasons.map((x) => h("li", null, x)))] : null);
}

function triageCard(repo) {
  const save = async (body) => {
    try {
      await api("/api/repo", Object.assign({ key: repo.key }, body));
      await openDetail(repo.key, true);
      loadRepos();
    } catch (err) {
      alertLine(err.message);
    }
  };
  const statuses = ["new", "shortlist", "digging", "reported", "skipped"];
  const notes = h("textarea", { placeholder: "Notes: what you checked, what you found" });
  notes.value = repo.notes || "";
  const saved = h("span", { class: "muted" });
  return h("section", { class: "card" },
    h("h2", null, "Triage"),
    h("div", { class: "actions" }, statuses.map((st) =>
      h("button", { class: "btn" + (repo.status === st ? " on" : ""), onclick: () => save({ status: st }) }, st))),
    h("div", { class: "actions" },
      h("button", { class: "btn real" + (repo.verdict === "real" ? " on" : ""),
        onclick: () => save({ verdict: repo.verdict === "real" ? "" : "real" }) }, "Real lead"),
      h("button", { class: "btn dud" + (repo.verdict === "dud" ? " on" : ""),
        onclick: () => save({ verdict: repo.verdict === "dud" ? "" : "dud" }) }, "Dud"),
      h("span", { class: "muted" }, " Marks teach the ranking which signals pay off.")),
    notes,
    h("div", { class: "actions" },
      h("button", { class: "btn", onclick: async () => {
        try {
          await api("/api/repo", { key: repo.key, notes: notes.value });
          saved.textContent = "saved";
        } catch (err) { saved.textContent = err.message; }
      } }, "Save notes"), saved));
}

async function openDetail(key, keepScroll) {
  const view = document.getElementById("detail-view");
  let repo;
  try {
    repo = await api("/api/repo?key=" + encodeURIComponent(key));
  } catch (err) {
    view.replaceChildren(h("a", { class: "back", href: "#" }, "← back"), h("p", null, err.message));
    return;
  }
  const y = window.scrollY;
  fillView(view, 
    h("a", { class: "back", href: "#" }, "← back to list"),
    h("div", { class: "dhead" },
      h("div", { class: "score" + (repo.score && repo.score.partial ? " partial" : "") }, fmtScore(repo.score)),
      h("div", null,
        h("h1", null, safeURL(repo.url) ? ext(repo.url, repo.name) : repo.name),
        repo.description ? h("div", { class: "muted" }, repo.description) : null)),
    triageCard(repo),
    findingsCard(repo),
    hotCard(repo),
    knownCard(repo),
    reportCard(repo),
    partsCard(repo),
    factsCard(repo),
    hitsCard(repo));
  if (!keepScroll) window.scrollTo(0, 0); else window.scrollTo(0, y);
}

// ---------- run panel ----------

function alertLine(msg, warn = true) {
  const log = document.getElementById("log");
  log.append(h("li", { class: warn ? "warn" : "" }, msg));
  while (log.children.length > 200) log.firstChild.remove();
  log.scrollTop = log.scrollHeight;
}

function showProgress(p) {
  state.running = p.running;
  const label = p.running
    ? p.stage + (p.total ? " " + p.done + "/" + p.total : "")
    : (p.stage || "idle");
  document.getElementById("runstate").textContent = label;
  document.getElementById("runbar").style.width = p.running && p.total ? (100 * p.done / p.total) + "%" : "0";
}

async function loadState() {
  state.info = await api("/api/state");
  showProgress(state.info.progress);
  const cats = state.info.categories || [];
  const fill = (sel, first) => {
    const cur = sel.value;
    sel.replaceChildren(first, ...cats.map((c) => h("option", { value: c.id }, c.name)));
    sel.value = cur;
  };
  const fs = document.getElementById("f-scene");
  const cur = fs.value;
  fill(fs, h("option", { value: "" }, "All scenes"));
  fs.append(h("option", { value: "variants" }, "Variant candidates"));
  fs.value = cur;
  fill(document.getElementById("runscene"), h("option", { value: "" }, "Every enabled scene"));
}

function listen() {
  const es = new EventSource("/api/events");
  let reloadTimer = null;
  const reloadSoon = () => {
    if (reloadTimer) return;
    reloadTimer = setTimeout(() => { reloadTimer = null; loadRepos(); }, 15000);
  };
  es.onmessage = (m) => {
    let e;
    try { e = JSON.parse(m.data); } catch { return; }
    if (e.type === "log") alertLine(e.msg, e.level === "warn");
    if (e.type === "progress") {
      showProgress({ running: true, stage: e.stage, done: e.done, total: e.total });
      reloadSoon();
    }
    if (e.type === "state") {
      showProgress({ running: false, stage: e.msg });
      loadState();
      loadRepos();
      if (document.getElementById("feed").open) loadFeed();
    }
  };
}

// ---------- variant hunt ----------

async function previewVariant() {
  const ref = document.getElementById("v-ref").value.trim();
  const box = document.getElementById("v-plan");
  if (!ref) return;
  box.hidden = true;
  let plan;
  try {
    plan = await api("/api/variant", { ref });
  } catch (err) { alertLine(err.message); return; }
  const cwes = (plan.cwes || []).join(", ");
  document.getElementById("v-summary").textContent =
    plan.ref + " in " + plan.repo + (plan.summary ? ": " + plan.summary : "") + (cwes ? " (" + cwes + ")" : "");
  document.getElementById("v-lines").replaceChildren(
    h("p", { class: "muted" }, "Lines the fix removed (-) or left around its change; a bar marks a dangerous call:"),
    ...(plan.removed || []).slice(0, 8).map((l) =>
      h("div", { class: "snip" + (l.sink ? " sink" : ""), title: l.path }, (l.context ? "  " : "- ") + l.text)));
  document.getElementById("v-queries").value = (plan.queries || []).join("\n");
  box.hidden = false;
}

// ---------- variant feed ----------

async function loadFeed() {
  let f;
  try { f = await api("/api/feed"); } catch (err) { alertLine(err.message); return; }
  const when = (iso) => (iso ? new Date(iso).toLocaleString() : "");
  document.getElementById("feed-status").textContent = !f.enabled
    ? "Off (turn it on in Settings)."
    : f.last_check ? "Last checked " + when(f.last_check) + ", next after " + when(f.next_check) + "." : "Not checked yet; the first check looks back a week.";
  const items = f.items || [];
  const showCandidates = (ghsa) => {
    document.getElementById("q").value = ghsa;
    document.getElementById("f-scene").value = "variants";
    state.shown = PAGE;
    renderList();
    document.getElementById("list-view").scrollIntoView();
  };
  const handHunt = (ghsa) => {
    document.getElementById("v-ref").value = ghsa;
    document.querySelector("details.variant").open = true;
    previewVariant();
  };
  document.getElementById("feed-items").replaceChildren(
    ...(items.length ? [] : [h("li", { class: "muted" }, "Nothing yet.")]),
    ...items.slice(0, 60).map((it) => h("li", { class: it.status },
      h("div", {},
        h("span", { class: "chip" + (it.status === "hunted" ? " good" : "") }, it.status),
        " ", ext(it.url || "https://github.com/advisories/" + it.ghsa, it.ghsa),
        " ", h("span", { class: "muted" }, [it.severity, it.class, it.package].filter(Boolean).join(" · "))),
      h("div", {}, it.summary),
      it.status === "hunted"
        ? h("div", { class: "muted" }, it.found + " candidate repos (" + it.new + " new) ",
            it.found ? h("button", { class: "btn small", onclick: () => showCandidates(it.ghsa) }, "Show") : null)
        : h("div", { class: "muted" }, it.reason + " ",
            h("button", { class: "btn small", onclick: () => handHunt(it.ghsa) }, "Hunt by hand")))));
}

// ---------- wiring ----------

function route() {
  const hash = location.hash;
  let m, view = "list";
  state.detailKey = null;
  if ((m = hash.match(/^#repo=(.+)$/))) {
    view = "detail";
    state.detailKey = decodeURIComponent(m[1]);
    openDetail(state.detailKey);
  } else if ((m = hash.match(/^#lib=(\w+)\/(.+)$/))) {
    view = "library";
    openLibEditor(m[1], decodeURIComponent(m[2]));
  } else if ((m = hash.match(/^#lib-new=(\w+)$/))) {
    view = "library";
    openLibEditor(m[1], null);
  } else if (hash === "#library") {
    view = "library";
    openLibrary();
  } else if (hash === "#settings") {
    view = "settings";
    openSettings();
  }
  for (const v of ["list", "detail", "library", "settings"]) document.getElementById(v + "-view").hidden = v !== view;
  const tab = view === "detail" ? "list" : view;
  for (const a of document.querySelectorAll(".nav a")) a.classList.toggle("on", a.dataset.view === tab);
  if (view !== "detail") window.scrollTo(0, 0);
}

function init() {
  for (const id of ["q", "f-scene", "f-status", "f-verdict", "f-sort", "f-confirmed", "f-high", "f-all", "f-unscanned"]) {
    document.getElementById(id).addEventListener(id === "q" ? "input" : "change", () => {
      state.shown = PAGE;
      renderList();
    });
  }
  document.getElementById("more").addEventListener("click", () => { state.shown += PAGE; renderList(); });
  document.getElementById("runtoggle").addEventListener("click", () => {
    const p = document.getElementById("runpanel");
    p.hidden = !p.hidden;
  });
  document.getElementById("runstart").addEventListener("click", async () => {
    const scene = document.getElementById("runscene").value;
    const stages = ["search", "enrich", "scan", "taint"].filter((s) => document.getElementById("st-" + s).checked);
    try {
      await api("/api/run", { stages, categories: scene ? [scene] : [], force: document.getElementById("st-force").checked });
    } catch (err) { alertLine(err.message); }
  });
  document.getElementById("runcancel").addEventListener("click", () => api("/api/run/cancel", {}).catch((e) => alertLine(e.message)));
  document.getElementById("feed").addEventListener("toggle", (e) => { if (e.target.open) loadFeed(); });
  document.getElementById("feed-run").addEventListener("click", () => api("/api/feed/run", {}).catch((e) => alertLine(e.message)));
  document.getElementById("v-preview").addEventListener("click", previewVariant);
  document.getElementById("v-ref").addEventListener("keydown", (e) => { if (e.key === "Enter") previewVariant(); });
  document.getElementById("v-hunt").addEventListener("click", async () => {
    const variant = document.getElementById("v-ref").value.trim();
    const queries = document.getElementById("v-queries").value.split("\n").map((q) => q.trim()).filter(Boolean);
    const stages = ["enrich", "scan", "taint"].filter((s) => document.getElementById("st-" + s).checked);
    try {
      await api("/api/run", { stages, variant, variant_queries: queries });
    } catch (err) { alertLine(err.message); }
  });
  window.addEventListener("hashchange", route);

  loadState().catch((e) => alertLine(e.message));
  loadRepos().catch((e) => alertLine(e.message));
  listen();
  route();
}

// library.js and settings.js load after this file
document.addEventListener("DOMContentLoaded", init);
