package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestFeedPicks(t *testing.T) {
	var advs []ghGlobalAdvisory
	_ = json.Unmarshal([]byte(`[
	 {"ghsa_id":"GHSA-aaaa-aaaa-aaaa","summary":"Grid parses labels as HTML","severity":"high",
	  "references":["https://github.com/x/grid/commit/abcdef1"],"cwes":[{"cwe_id":"CWE-79"}],
	  "vulnerabilities":[{"package":{"ecosystem":"npm","name":"grid"}}]},
	 {"ghsa_id":"GHSA-bbbb-bbbb-bbbb","summary":"mcp-files: path traversal in read_file","severity":"medium",
	  "references":["https://github.com/x/mcp-files/pull/12"],"cwes":[{"cwe_id":"CWE-79"},{"cwe_id":"CWE-22"}],
	  "vulnerabilities":[{"package":{"ecosystem":"npm","name":"mcp-files"}}]},
	 {"ghsa_id":"GHSA-cccc-cccc-cccc","summary":"no fix linked","severity":"critical",
	  "references":["https://example.com/blog"],"cwes":[{"cwe_id":"CWE-78"}],
	  "vulnerabilities":[{"package":{"ecosystem":"pip","name":"tool"}}]},
	 {"ghsa_id":"GHSA-dddd-dddd-dddd","summary":"rust crate","severity":"critical",
	  "references":["https://github.com/x/zip/commit/abcdef1"],"cwes":[{"cwe_id":"CWE-22"}],
	  "vulnerabilities":[{"package":{"ecosystem":"rust","name":"zip"}}]},
	 {"ghsa_id":"GHSA-eeee-eeee-eeee","summary":"Duplicate Advisory: whatever","severity":"high",
	  "references":["https://github.com/x/y/commit/abcdef1"],"cwes":[{"cwe_id":"CWE-22"}],
	  "vulnerabilities":[{"package":{"ecosystem":"npm","name":"y"}}]},
	 {"ghsa_id":"GHSA-ffff-ffff-ffff","summary":"seen before","severity":"high",
	  "references":["https://github.com/x/z/commit/abcdef1"],"cwes":[{"cwe_id":"CWE-22"}],
	  "vulnerabilities":[{"package":{"ecosystem":"npm","name":"z"}}]}
	]`), &advs)
	cweClass := map[string]string{"CWE-79": "xss", "CWE-22": "path-traversal", "CWE-78": "cmd-exec"}
	picks, skipped := feedPicks(advs, cweClass, map[string]bool{"GHSA-ffff-ffff-ffff": true})
	if len(picks) != 2 {
		t.Fatalf("picks = %+v", picks)
	}
	// a medium path traversal in an MCP package beats a high XSS in a chart library
	if p := picks[0].item; p.GHSA != "GHSA-bbbb-bbbb-bbbb" || p.Class != "path-traversal" || p.Ecosystem != "npm" {
		t.Errorf("first pick = %+v", p)
	}
	if len(skipped) != 1 || skipped[0].GHSA != "GHSA-cccc-cccc-cccc" || skipped[0].Reason == "" {
		t.Errorf("skipped = %+v", skipped)
	}
}

func TestNextLink(t *testing.T) {
	hd := http.Header{}
	hd.Set("Link", `<https://api.github.com/advisories?after=Y3Vy&per_page=100>; rel="next", <https://api.github.com/advisories?per_page=100>; rel="prev"`)
	if got := nextLink(hd); got != "https://api.github.com/advisories?after=Y3Vy&per_page=100" {
		t.Errorf("next = %q", got)
	}
	hd.Set("Link", `<https://evil.example/x>; rel="next"`)
	if got := nextLink(hd); got != "" {
		t.Errorf("followed a link off GitHub: %q", got)
	}
}

func TestFeedStateRoundTrip(t *testing.T) {
	a := testApp(t)
	st := a.feedState()
	st.Items = append(st.Items, FeedItem{GHSA: "GHSA-aaaa-aaaa-aaaa", Status: "hunted", Found: 3})
	a.saveFeedState(st)
	if got := a.feedState(); len(got.Items) != 1 || got.Items[0].Found != 3 {
		t.Errorf("state = %+v", got)
	}
}
