"use strict";

// Settings: one form over /api/settings. The token field is write-only; the server never sends it.

const SETTINGS_FORM = [
  ["Search", [
    ["max_results_per_query", "num", "Results per query", "GitHub stops at 1000 per query; a dork file can set its own."],
    ["search_sort", ["best-match", "updated", "stars"], "GitHub sort", "updated finds live projects first."],
    ["auto_split", "bool", "Split queries over 1000 results by star ranges"],
  ]],
  ["Filters", [
    ["max_days_since_push", "num", "Max days since last push", "Also fills {{since}} in dork files."],
    ["maintainer_window_days", "num", "Maintainer activity window (days)"],
    ["require_maintainer_activity", "bool", "Drop repos whose maintainer hasn't replied to anyone in that window"],
    ["require_release_or_tag", "bool", "Drop repos with no release or tag (nothing shipped, nothing to get a CVE for)"],
    ["contact_kinds", "list", "What counts as a private contact", "pvr, security_policy, email, discord, telegram, matrix, twitter, bluesky"],
    ["language_allow", "list", "Only these languages (empty = all)", "e.g. Python, TypeScript, Go"],
    ["ignore_list", "lines", "Ignore list", "One per line: owner, owner/repo, wp:slug or jk:id"],
  ]],
  ["Enrichment", [
    ["check_pvr", "bool", "Check whether private vulnerability reporting is on"],
    ["check_advisories", "bool", "Look up past advisories and open security issues"],
    ["refresh_after_days", "num", "Refresh repo details after (days)"],
    ["skip_reviewed", "bool", "Don't refresh repos you've marked or moved on"],
    ["graphql_batch", "num", "Repos per GraphQL request (1–25)"],
  ]],
  ["Scan", [
    ["scan_enabled", "bool", "Download and scan the code of repos that pass the filters"],
    ["max_repo_size_mb", "num", "Skip repos bigger than (MB)"],
    ["scan_max_file_kb", "num", "Skip files bigger than (KB)"],
    ["skip_tests", "bool", "Skip test folders"],
    ["concurrency", "num", "Parallel downloads (1–16)"],
  ]],
  ["Semgrep", [
    ["semgrep_auto", "bool", "Confirm findings with Semgrep after a scan"],
    ["semgrep_top_n", "num", "How many top repos to confirm"],
    ["semgrep_path", "text", "Semgrep binary (empty = PATH, then sift's own venv)"],
  ]],
  ["Variant feed", [
    ["variant_feed", "bool", "Once a day, hunt variants of new advisories sift's checkers understand"],
    ["feed_per_day", "num", "Hunts per daily check (best advisories first)"],
  ]],
  ["Ranking", [
    ["score_cve_path", "bool", "Score how a finding would become a CVE"],
  ]],
];

async function openSettings() {
  const view = document.getElementById("settings-view");
  try {
    state.info = await api("/api/state");
  } catch (err) {
    fillView(view, h("p", null, err.message));
    return;
  }
  const s = structuredClone(state.info.settings);
  const status = h("span", { class: "muted" });
  const input = ([key, type, label, hint]) => {
    if (type === "bool") return h("div", null, checkIn(s, key, label), hint ? h("small", { class: "muted" }, " " + hint) : null);
    let el;
    if (Array.isArray(type)) el = selectIn(s, key, type.map((o) => [o, o]));
    else if (type === "num") el = numIn(s, key);
    else if (type === "lines") el = linesIn(s, key);
    else if (type === "list") {
      el = h("input", { type: "text", spellcheck: "false" });
      el.value = (s[key] || []).join(", ");
      el.addEventListener("input", () => { s[key] = el.value.split(",").map((x) => x.trim()).filter(Boolean); });
    } else el = textIn(s, key);
    return field(label, el, hint);
  };
  const w = s.weights || {};
  const weights = h("div", { class: "row3" }, Object.keys(w).map((k) => field(PART_LABELS[k] || k, numIn(w, k))));
  const token = h("input", { type: "password", autocomplete: "off", placeholder: state.info.token_source ? "set (" + state.info.token_source + ")" : "not set" });
  const save = async () => {
    status.textContent = "saving…";
    const body = Object.assign({}, s);
    for (const k of ["overrides", "disabled_queries", "disabled_files", "token"]) delete body[k];
    // an unticked box or cleared list means off/empty; a cleared number keeps its old value
    for (const [, fields] of SETTINGS_FORM) for (const [k, type] of fields) {
      if (body[k] === undefined) body[k] = type === "bool" ? false : type === "num" ? state.info.settings[k] : (type === "list" || type === "lines") ? [] : "";
    }
    for (const k of Object.keys(state.info.settings.weights)) if (w[k] === undefined) w[k] = state.info.settings.weights[k];
    if (token.value.trim()) body.token = token.value.trim();
    try {
      await api("/api/settings", body);
      token.value = "";
      status.textContent = "saved";
      openSettings();
      loadRepos();
    } catch (err) { status.textContent = err.message; }
  };
  fillView(view, 
    h("h1", { class: "edtitle" }, "Settings"),
    h("section", { class: "card form" },
      h("h2", null, "GitHub token"),
      field("Token", token, state.info.token_source && state.info.token_source.startsWith("env")
        ? "Comes from the environment (" + state.info.token_source + "), which wins over anything saved here."
        : "Read-only access to public repos is all sift needs. Stored in data/settings.json, never sent back to the browser.")),
    SETTINGS_FORM.map(([title, fields]) => h("section", { class: "card form" }, h("h2", null, title), fields.map(input))),
    h("section", { class: "card form" }, h("h2", null, "Score weights"),
      h("p", { class: "muted" }, "How much each signal counts in a repo's score. 0 turns one off. Saving rescores everything."), weights),
    h("div", { class: "actions sticky" }, h("button", { class: "btn primary", onclick: save }, "Save settings"), status));
}
