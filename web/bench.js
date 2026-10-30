"use strict";

// ---------- bench (plan 17): how the checkers do on real, fixed advisories ----------

const BENCH_RESULT = {
  cleared: ["caught", "good"],
  still: ["caught, still flagged after the fix", "warn"],
  other: ["another checker fired", ""],
  missed: ["missed", "bad"],
};
const BENCH_WHY = {
  "no-sink": "no checker sink near the change (the fix tightened a validator, or the call is unknown)",
  "no-input": "a sink is there, but no input sift recognises reaches it",
  flow: "sink and input both there: an engine gap",
};

function benchCard() {
  const card = h("section", { class: "card", id: "bench" }, h("h2", null, "Bench"), h("p", { class: "muted" }, "Loading…"));
  loadBench(card);
  return card;
}

async function loadBench(card) {
  let b;
  try { b = await api("/api/bench"); } catch (err) { fillView(card, h("h2", null, "Bench"), h("p", null, err.message)); return; }
  const rep = b.report;
  const hist = b.history || [];
  // the last scored checker set before this one, to show what a change did
  let prev = null;
  for (let i = hist.length - 2; i >= 0 && rep; i--) {
    if (hist[i].fingerprint !== rep.fingerprint) { prev = hist[i]; break; }
  }
  const score = h("button", { class: "btn", onclick: async () => {
    score.disabled = true;
    try { await api("/api/bench/run", {}); } catch (err) { alertLine(err.message); }
    loadBench(card);
  } }, "Score again");
  const collect = h("button", { class: "btn", disabled: b.collecting, onclick: async () => {
    try {
      await api("/api/bench/collect", { days: 90 });
      alertLine("collecting the last 90 days of advisories; the run log shows progress", false);
      collect.disabled = true;
    } catch (err) { alertLine(err.message); }
  } }, b.collecting ? "Collecting…" : "Collect 90 days");
  const pct = (a, n) => (n ? Math.round((100 * a) / n) + "%" : "–");
  const delta = (now, then) => {
    if (then == null || now === then) return null;
    const d = now - then;
    return h("span", { class: "chip " + (d > 0 ? "good" : "bad") }, (d > 0 ? "+" : "") + d);
  };
  fillView(card,
    h("div", { class: "libhead" }, h("h2", null, "Bench"), h("span", { class: "row" }, score, " ", collect)),
    h("p", { class: "muted" },
      "Real advisories with their fix commit: does a checker flag the code before the fix, near what it changed, and go quiet after it? ",
      b.corpus + " cases in data/bench, refreshed by the variant feed every day. Nothing in them is ever run."),
    !rep ? h("p", null, "Not scored yet.") : [
      h("p", null, h("b", null, rep.caught + " of " + rep.covered_cases), " bugs in classes sift checks were caught (",
        pct(rep.caught, rep.covered_cases), "), ", rep.cleared, " of them quiet after the fix. ",
        prev ? ["Since the last checker set: ", delta(rep.caught, prev.caught) || "no change", "."] : null,
        h("span", { class: "muted" }, " Scored " + new Date(rep.at).toLocaleString() + ".")),
      h("div", { class: "tablewrap" }, h("table", { class: "bench" },
        h("thead", null, h("tr", null, ["class", "cases", "caught", "quiet after fix", "still flagged", ""].map((t) => h("th", null, t)))),
        h("tbody", null, (rep.classes || []).map((c) => h("tr", { class: c.covered ? "" : "muted" },
          h("td", null, c.class, c.covered ? null : " (no checker)"),
          h("td", null, c.cases),
          h("td", null, c.caught + " (" + pct(c.caught, c.cases) + ")"),
          h("td", null, c.cleared),
          h("td", null, c.still_after),
          h("td", null, prev ? delta(c.caught, (prev.by_class || {})[c.class] || 0) : null)))))),
      benchList(rep),
    ]);
}

function benchList(rep) {
  const shown = (rep.results || []).filter((r) => r.result !== "cleared").slice(0, 80);
  return h("details", null,
    h("summary", null, "Misses and fixes sift doesn't see (" + shown.length + " shown)"),
    h("ul", { class: "plain benchlist" }, shown.map((r) => {
      const [label, cls] = BENCH_RESULT[r.result] || [r.result, ""];
      return h("li", null,
        h("span", { class: "chip " + cls }, label), " ",
        r.why ? h("span", { class: "chip", title: BENCH_WHY[r.why] || "" }, r.why) : null, " ",
        ext("https://github.com/advisories/" + r.ghsa, r.ghsa), " ",
        h("span", { class: "muted" }, (r.classes || []).join(", ")),
        h("div", null, r.summary),
        (r.findings || r.removed || []).slice(0, 3).map((l) => h("div", { class: "snip" }, l)),
        r.fix ? h("div", null, ext(r.fix, "fix commit")) : null);
    })));
}
