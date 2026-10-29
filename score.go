package main

import (
	"fmt"
	"math"
	"strings"
	"time"
)

func logScale(x, cap float64) float64 {
	if x <= 0 {
		return 0
	}
	v := 10 * math.Log1p(x) / math.Log1p(cap)
	return math.Min(10, v)
}

func daysSince(t time.Time) float64 {
	if t.IsZero() {
		return math.Inf(1)
	}
	return time.Since(t).Hours() / 24
}

// Score parts are each 0–10. The total is the weighted average scaled to 0–100.
// Missing parts (e.g. code parts of a repo that wasn't scanned) count as zero, and the score is
// marked partial. Averaging over only the parts we have would let an unscanned repo with good
// metadata (fresh, PVR, active maintainer) outrank repos whose code we actually looked at.
func computeScore(r *Repo, s Settings, contactHandledByProgram bool) *Score {
	parts := map[string]float64{}
	w := s.Weights

	// Caps sit near the top few percent of a real MCP run (~500 repos), so the top end still
	// spreads out instead of everything big pinning at 10.
	if r.Scan != nil && r.Scan.Error == "" {
		parts["sinks"] = logScale(r.Scan.WeightedSinks, 1200)
		parts["surface"] = logScale(float64(r.Scan.SurfaceHits), 450)
		parts["auth"] = logScale(float64(r.Scan.AuthHits), 450)
		parts["pairing"] = logScale(r.Scan.PairedWeight, 150)
	}
	e := r.Enriched
	if e != nil {
		// A past advisory or two means the code has had real bugs and the maintainer handled a
		// report. Many means other people are already combing through it.
		switch {
		case e.Advisories <= 0:
			parts["history"] = 4
		case e.Advisories <= 2:
			parts["history"] = 10
		case e.Advisories == 3:
			parts["history"] = 7
		case e.Advisories <= 5:
			parts["history"] = 5
		case e.Advisories <= 9:
			parts["history"] = 3
		default:
			parts["history"] = 1
		}
		if contactHandledByProgram {
			parts["responsiveness"] = 5 // neutral: Wordfence / the Jenkins security team chase the vendor, not you
		} else if e.MaintainerLastReply != nil {
			d := daysSince(*e.MaintainerLastReply)
			switch {
			case d <= 14:
				parts["responsiveness"] = 10
			case d <= 30:
				parts["responsiveness"] = 8
			case d <= 90:
				parts["responsiveness"] = 5
			case d <= 180:
				parts["responsiveness"] = 2
			default:
				parts["responsiveness"] = 0
			}
		} else if e.IssuesSeen == 0 {
			parts["responsiveness"] = 3 // nothing to judge by
		} else {
			parts["responsiveness"] = 0
		}
		d := daysSince(e.PushedAt)
		switch {
		case d <= 7:
			parts["freshness"] = 10
		case d <= 30:
			parts["freshness"] = 8
		case d <= 60:
			parts["freshness"] = 5
		case d <= 120:
			parts["freshness"] = 2
		default:
			parts["freshness"] = 0
		}
	}
	if contactHandledByProgram {
		parts["contact"] = 10
	} else {
		best := 0.0
		for _, c := range r.Contacts {
			v := map[string]float64{"pvr": 10, "security_policy": 8, "email": 6, "discord": 4, "telegram": 4, "matrix": 4, "twitter": 3, "bluesky": 3, "mastodon": 3, "website": 2}[c.Kind]
			best = math.Max(best, v)
		}
		parts["contact"] = best
	}

	weights := map[string]float64{
		"sinks": w.Sinks, "surface": w.Surface, "auth": w.Auth, "pairing": w.Pairing, "history": w.History,
		"responsiveness": w.Responsiveness, "freshness": w.Freshness, "contact": w.Contact,
	}
	if s.ScoreCVEPath {
		_, parts["cve_path"] = cvePath(r)
		weights["cve_path"] = w.CVEPath
	}
	var sum, wsum float64
	for k, wt := range weights {
		if wt <= 0 {
			continue
		}
		sum += parts[k] * wt // absent part = 0
		wsum += wt
	}
	total := 0.0
	if wsum > 0 {
		total = sum / wsum * 10
	}
	_, scanned := parts["sinks"]
	return &Score{Total: math.Round(total*10) / 10, Parts: parts, Partial: !scanned, At: time.Now()}
}

// cvePath says how a bug found in r would most likely end up as a CVE, and how good that route is (0–10).
// A CNA on the path (GitHub via a repo security advisory, Wordfence/Patchstack/WPScan for WordPress,
// the Jenkins project for its plugins) assigns the CVE as part of the fix. Without one you're filing
// the MITRE form yourself and waiting.
func cvePath(r *Repo) (string, float64) {
	switch r.Source {
	case "wordpress":
		return "wordpress-cna", 10
	case "jenkins":
		return "jenkins-cna", 10
	}
	e := r.Enriched
	if e == nil {
		return "", 0
	}
	switch {
	case e.PVR != nil && *e.PVR:
		return "github-pvr", 10 // report privately, maintainer publishes a GHSA, GitHub assigns the CVE
	case e.Advisories > 0:
		return "github-advisory", 8 // no PVR, but they've published GHSAs before and know the flow
	case e.HasSecurityPolicy:
		return "security-policy", 6
	}
	for _, c := range r.Contacts {
		if c.Kind != "profile" && c.Kind != "website" {
			return "mitre", 3
		}
	}
	return "none", 0
}

// applyFilters decides whether a repo stays on the list, with a reason for every drop.
func applyFilters(r *Repo, s Settings, requireContact bool) FilterResult {
	var reasons []string
	key := strings.ToLower(r.Key)
	name := strings.ToLower(r.Name)
	owner := strings.ToLower(r.Owner)
	for _, ig := range s.IgnoreList {
		ig = strings.ToLower(strings.TrimSpace(ig))
		if ig == "" {
			continue
		}
		if ig == key || ig == name || ig == owner || (r.GitHubRepo != "" && ig == strings.ToLower(r.GitHubRepo)) {
			reasons = append(reasons, "on the ignore list")
		}
	}
	e := r.Enriched
	if e != nil {
		if e.Error != "" && r.Source == "github" {
			reasons = append(reasons, "couldn't fetch metadata: "+e.Error)
		}
		if e.Archived {
			reasons = append(reasons, "archived")
		}
		if e.Fork {
			reasons = append(reasons, "fork")
		}
		if r.Source == "github" && s.MaxDaysSincePush > 0 && daysSince(e.PushedAt) > float64(s.MaxDaysSincePush) {
			reasons = append(reasons, fmt.Sprintf("no push in %d+ days", s.MaxDaysSincePush))
		}
		if r.Source != "wordpress" && s.RequireReleaseOrTag && e.Error == "" && e.Releases+e.Tags == 0 && r.Source == "github" {
			reasons = append(reasons, "no releases or tags")
		}
		// Only for repos where *we* must reach the maintainer. Jenkins/Wordfence handle that themselves,
		// and Jenkins even publishes advisories (with CVEs) for plugins nobody maintains.
		if r.Source == "github" && s.RequireMaintainerActivity && e.Error == "" && e.IssuesSeen > 0 {
			if e.MaintainerLastReply == nil || daysSince(*e.MaintainerLastReply) > float64(s.MaintainerWindowDays) {
				reasons = append(reasons, fmt.Sprintf("no maintainer reply on issues/PRs in %d days", s.MaintainerWindowDays))
			}
		}
	} else if r.Source == "github" {
		reasons = append(reasons, "not enriched yet")
	}
	if len(s.LanguageAllow) > 0 && r.Language != "" {
		ok := false
		for _, l := range s.LanguageAllow {
			if strings.EqualFold(strings.TrimSpace(l), r.Language) {
				ok = true
			}
		}
		if !ok {
			reasons = append(reasons, "language "+r.Language+" not in the allow list")
		}
	}
	if requireContact && !hasQualifyingContact(r.Contacts, s.ContactKinds) {
		reasons = append(reasons, "no private contact found")
	}
	return FilterResult{Pass: len(reasons) == 0, Reasons: reasons}
}
