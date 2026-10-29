package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const userAgent = "sift/" + version + " (repo triage tool)"

// HTTP wraps a client with GitHub-aware rate limit handling. It is also used for WordPress/Jenkins.
type HTTP struct {
	client *http.Client
	token  string
	log    func(string, ...any)

	mu     sync.Mutex
	waitTo map[string]time.Time // resource -> don't call before
}

func newHTTP(token string, logf func(string, ...any)) *HTTP {
	return &HTTP{
		client: &http.Client{Timeout: 90 * time.Second},
		token:  token,
		log:    logf,
		waitTo: map[string]time.Time{},
	}
}

func ghResource(u *url.URL) string {
	if u.Host != "api.github.com" {
		return ""
	}
	switch {
	case strings.HasPrefix(u.Path, "/search/"):
		return "search"
	case u.Path == "/graphql":
		return "graphql"
	default:
		return "core"
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Do sends a request, waiting out rate limits and retrying transient failures.
// body may be nil; it is re-sent on retries.
func (h *HTTP) Do(ctx context.Context, method, rawURL string, body []byte, accept string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	res := ghResource(u)
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		if res != "" {
			h.mu.Lock()
			until := h.waitTo[res]
			h.mu.Unlock()
			if d := time.Until(until); d > 0 {
				h.log("GitHub %s rate limit reached, waiting %s", res, d.Round(time.Second))
				if err := sleepCtx(ctx, d); err != nil {
					return nil, err
				}
			}
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if res != "" {
			if accept == "" {
				accept = "application/vnd.github+json"
			}
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
			if h.token != "" {
				req.Header.Set("Authorization", "Bearer "+h.token)
			}
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := h.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			if err := sleepCtx(ctx, time.Duration(2<<attempt)*time.Second); err != nil {
				return nil, err
			}
			continue
		}
		if res != "" {
			h.trackLimits(res, resp)
		}
		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			wait := h.retryWait(resp, b)
			if wait > 0 && wait < 20*time.Minute {
				lastErr = fmt.Errorf("rate limited (%d)", resp.StatusCode)
				h.log("rate limited by %s, retrying in %s", u.Host, wait.Round(time.Second))
				if err := sleepCtx(ctx, wait); err != nil {
					return nil, err
				}
				continue
			}
			return nil, fmt.Errorf("%s %s: %d %s", method, u.Path, resp.StatusCode, firstLine(b))
		}
		if resp.StatusCode >= 500 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			lastErr = fmt.Errorf("%s %s: %d %s", method, u.Path, resp.StatusCode, firstLine(b))
			if err := sleepCtx(ctx, time.Duration(2<<attempt)*time.Second); err != nil {
				return nil, err
			}
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("gave up after retries: %w", lastErr)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func (h *HTTP) trackLimits(res string, resp *http.Response) {
	rem := resp.Header.Get("X-RateLimit-Remaining")
	reset := resp.Header.Get("X-RateLimit-Reset")
	if r := resp.Header.Get("X-RateLimit-Resource"); r != "" {
		if r == "code_search" {
			res = "search"
		} else if r == "core" || r == "search" || r == "graphql" {
			res = r
		}
	}
	if rem == "0" && reset != "" {
		if sec, err := strconv.ParseInt(reset, 10, 64); err == nil {
			h.mu.Lock()
			h.waitTo[res] = time.Unix(sec, 0).Add(2 * time.Second)
			h.mu.Unlock()
		}
	}
}

func (h *HTTP) retryWait(resp *http.Response, body []byte) time.Duration {
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if sec, err := strconv.Atoi(ra); err == nil {
			return time.Duration(sec)*time.Second + time.Second
		}
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if sec, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			return time.Until(time.Unix(sec, 0)) + 2*time.Second
		}
	}
	if bytes.Contains(bytes.ToLower(body), []byte("secondary rate limit")) || resp.StatusCode == 429 {
		return 60 * time.Second
	}
	return 0
}

func (h *HTTP) GetJSON(ctx context.Context, rawURL string, out any) (int, error) {
	resp, err := h.Do(ctx, "GET", rawURL, nil, "")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return resp.StatusCode, fmt.Errorf("GET %s: %d %s", rawURL, resp.StatusCode, firstLine(b))
	}
	return 200, json.NewDecoder(resp.Body).Decode(out)
}

// ---------- search ----------

type ghSearchItem struct {
	FullName        string    `json:"full_name"`
	HTMLURL         string    `json:"html_url"`
	Description     *string   `json:"description"`
	Language        *string   `json:"language"`
	StargazersCount int       `json:"stargazers_count"`
	PushedAt        time.Time `json:"pushed_at"`
	Archived        bool      `json:"archived"`
	Fork            bool      `json:"fork"`
	Homepage        *string   `json:"homepage"`
	Topics          []string  `json:"topics"`
	Owner           struct {
		Login   string `json:"login"`
		HTMLURL string `json:"html_url"`
	} `json:"owner"`
}

type ghSearchResp struct {
	TotalCount        int            `json:"total_count"`
	IncompleteResults bool           `json:"incomplete_results"`
	Items             []ghSearchItem `json:"items"`
}

func (h *HTTP) searchPage(ctx context.Context, q, sort string, page int) (ghSearchResp, error) {
	v := url.Values{}
	v.Set("q", q)
	v.Set("per_page", "100")
	v.Set("page", strconv.Itoa(page))
	if sort == "updated" || sort == "stars" {
		v.Set("sort", sort)
		v.Set("order", "desc")
	}
	var out ghSearchResp
	_, err := h.GetJSON(ctx, "https://api.github.com/search/repositories?"+v.Encode(), &out)
	return out, err
}

var starsRangeRe = regexp.MustCompile(`stars:(\d+)\.\.(\d+)`)

// SearchAll collects up to limit results for q (0 = as many as GitHub allows).
// With autoSplit, queries over the 1000-result cap with a stars:A..B range are bisected.
func (h *HTTP) SearchAll(ctx context.Context, q, sort string, limit int, autoSplit bool, depth int) ([]ghSearchItem, int, error) {
	first, err := h.searchPage(ctx, q, sort, 1)
	if err != nil {
		return nil, 0, err
	}
	total := first.TotalCount
	wantAll := limit <= 0 || limit > 1000
	if total > 1000 && wantAll && autoSplit && depth < 6 {
		if m := starsRangeRe.FindStringSubmatchIndex(q); m != nil {
			lo, _ := strconv.Atoi(q[m[2]:m[3]])
			hi, _ := strconv.Atoi(q[m[4]:m[5]])
			if hi > lo {
				mid := lo + (hi-lo)/2
				qa := q[:m[0]] + fmt.Sprintf("stars:%d..%d", lo, mid) + q[m[1]:]
				qb := q[:m[0]] + fmt.Sprintf("stars:%d..%d", mid+1, hi) + q[m[1]:]
				h.log("  %d results is over GitHub's 1000 cap, splitting into stars:%d..%d and stars:%d..%d", total, lo, mid, mid+1, hi)
				a, _, err := h.SearchAll(ctx, qa, sort, limit, autoSplit, depth+1)
				if err != nil {
					return nil, total, err
				}
				b, _, err := h.SearchAll(ctx, qb, sort, limit, autoSplit, depth+1)
				if err != nil {
					return a, total, err
				}
				items := append(a, b...)
				if limit > 0 && len(items) > limit {
					items = items[:limit]
				}
				return items, total, nil
			}
		} else if depth == 0 {
			h.log("  %d results but only 1000 are reachable; add a stars:A..B range to let sift split it", total)
		}
	}
	items := first.Items
	reachable := total
	if reachable > 1000 {
		reachable = 1000
	}
	for page := 2; len(items) < reachable && (limit <= 0 || len(items) < limit); page++ {
		r, err := h.searchPage(ctx, q, sort, page)
		if err != nil {
			return items, total, err
		}
		if len(r.Items) == 0 {
			break
		}
		items = append(items, r.Items...)
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, total, nil
}

// ---------- GraphQL enrichment ----------

const repoFragment = `
fragment R on Repository {
  nameWithOwner url description homepageUrl pushedAt isArchived isFork diskUsage stargazerCount
  primaryLanguage { name }
  licenseInfo { spdxId }
  repositoryTopics(first: 10) { nodes { topic { name } } }
  isSecurityPolicyEnabled securityPolicyUrl
  releases { totalCount }
  tags: refs(refPrefix: "refs/tags/", first: 1) { totalCount }
  openIssues: issues(states: OPEN) { totalCount }
  defaultBranchRef { name target { ... on Commit { oid history(since: "%s") { totalCount } } } }
  recentIssues: issues(first: 12, orderBy: {field: UPDATED_AT, direction: DESC}) { nodes { authorAssociation comments(last: 6) { nodes { authorAssociation createdAt } } } }
  recentPRs: pullRequests(first: 8, orderBy: {field: UPDATED_AT, direction: DESC}) { nodes { comments(last: 6) { nodes { authorAssociation createdAt } } } }
  readme1: object(expression: "HEAD:README.md") { ... on Blob { text } }
  readme2: object(expression: "HEAD:readme.md") { ... on Blob { text } }
  readme3: object(expression: "HEAD:README") { ... on Blob { text } }
  readme4: object(expression: "HEAD:README.rst") { ... on Blob { text } }
  sec1: object(expression: "HEAD:SECURITY.md") { ... on Blob { text } }
  sec2: object(expression: "HEAD:.github/SECURITY.md") { ... on Blob { text } }
  sec3: object(expression: "HEAD:docs/SECURITY.md") { ... on Blob { text } }
  funding: object(expression: "HEAD:.github/FUNDING.yml") { ... on Blob { text } }
  owner {
    login url
    ... on User { name email websiteUrl twitterUsername bio company socialAccounts(first: 10) { nodes { provider url displayName } } }
    ... on Organization { name email websiteUrl twitterUsername description }
  }
}`

type gqlBlob struct {
	Text *string `json:"text"`
}

type gqlComment struct {
	AuthorAssociation string    `json:"authorAssociation"`
	CreatedAt         time.Time `json:"createdAt"`
}

type gqlRepo struct {
	NameWithOwner   string     `json:"nameWithOwner"`
	URL             string     `json:"url"`
	Description     *string    `json:"description"`
	HomepageURL     *string    `json:"homepageUrl"`
	PushedAt        *time.Time `json:"pushedAt"`
	IsArchived      bool       `json:"isArchived"`
	IsFork          bool       `json:"isFork"`
	DiskUsage       int        `json:"diskUsage"`
	StargazerCount  int        `json:"stargazerCount"`
	PrimaryLanguage *struct {
		Name string `json:"name"`
	} `json:"primaryLanguage"`
	LicenseInfo *struct {
		SpdxID string `json:"spdxId"`
	} `json:"licenseInfo"`
	RepositoryTopics struct {
		Nodes []struct {
			Topic struct {
				Name string `json:"name"`
			} `json:"topic"`
		} `json:"nodes"`
	} `json:"repositoryTopics"`
	IsSecurityPolicyEnabled bool    `json:"isSecurityPolicyEnabled"`
	SecurityPolicyURL       *string `json:"securityPolicyUrl"`
	Releases                struct {
		TotalCount int `json:"totalCount"`
	} `json:"releases"`
	Tags struct {
		TotalCount int `json:"totalCount"`
	} `json:"tags"`
	OpenIssues struct {
		TotalCount int `json:"totalCount"`
	} `json:"openIssues"`
	DefaultBranchRef *struct {
		Name   string `json:"name"`
		Target struct {
			Oid     string `json:"oid"`
			History struct {
				TotalCount int `json:"totalCount"`
			} `json:"history"`
		} `json:"target"`
	} `json:"defaultBranchRef"`
	RecentIssues struct {
		Nodes []struct {
			Comments struct {
				Nodes []gqlComment `json:"nodes"`
			} `json:"comments"`
		} `json:"nodes"`
	} `json:"recentIssues"`
	RecentPRs struct {
		Nodes []struct {
			Comments struct {
				Nodes []gqlComment `json:"nodes"`
			} `json:"comments"`
		} `json:"nodes"`
	} `json:"recentPRs"`
	Readme1 *gqlBlob `json:"readme1"`
	Readme2 *gqlBlob `json:"readme2"`
	Readme3 *gqlBlob `json:"readme3"`
	Readme4 *gqlBlob `json:"readme4"`
	Sec1    *gqlBlob `json:"sec1"`
	Sec2    *gqlBlob `json:"sec2"`
	Sec3    *gqlBlob `json:"sec3"`
	Funding *gqlBlob `json:"funding"`
	Owner   struct {
		Login           string  `json:"login"`
		URL             string  `json:"url"`
		Name            *string `json:"name"`
		Email           *string `json:"email"`
		WebsiteURL      *string `json:"websiteUrl"`
		TwitterUsername *string `json:"twitterUsername"`
		Bio             *string `json:"bio"`
		Company         *string `json:"company"`
		Description     *string `json:"description"`
		SocialAccounts  *struct {
			Nodes []struct {
				Provider    string `json:"provider"`
				URL         string `json:"url"`
				DisplayName string `json:"displayName"`
			} `json:"nodes"`
		} `json:"socialAccounts"`
	} `json:"owner"`
}

func (r *gqlRepo) readme() string {
	for _, b := range []*gqlBlob{r.Readme1, r.Readme2, r.Readme3, r.Readme4} {
		if b != nil && b.Text != nil {
			return *b.Text
		}
	}
	return ""
}

func (r *gqlRepo) security() string {
	for _, b := range []*gqlBlob{r.Sec1, r.Sec2, r.Sec3} {
		if b != nil && b.Text != nil {
			return *b.Text
		}
	}
	return ""
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func gqlQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// EnrichBatch fetches metadata for several "owner/name" repos in one GraphQL call.
// The returned map has an entry per input; nil means not found / error (see errs).
func (h *HTTP) EnrichBatch(ctx context.Context, names []string, since time.Time) (map[string]*gqlRepo, map[string]string, error) {
	if h.token == "" {
		return nil, nil, errors.New("GraphQL needs a GitHub token (set one in Settings)")
	}
	var sb strings.Builder
	sb.WriteString("query {\n")
	for i, n := range names {
		owner, name, _ := strings.Cut(n, "/")
		fmt.Fprintf(&sb, "  r%d: repository(owner: %s, name: %s) { ...R }\n", i, gqlQuote(owner), gqlQuote(name))
	}
	sb.WriteString("  rateLimit { remaining resetAt cost }\n}\n")
	sb.WriteString(fmt.Sprintf(repoFragment, since.UTC().Format(time.RFC3339)))
	payload, _ := json.Marshal(map[string]string{"query": sb.String()})

	resp, err := h.Do(ctx, "POST", "https://api.github.com/graphql", payload, "application/json")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("graphql: %d %s", resp.StatusCode, firstLine(b))
	}
	var out struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
			Path    []any  `json:"path"`
			Type    string `json:"type"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, nil, fmt.Errorf("graphql decode: %w", err)
	}
	if out.Data == nil && len(out.Errors) > 0 {
		return nil, nil, fmt.Errorf("graphql: %s", out.Errors[0].Message)
	}
	if rl, ok := out.Data["rateLimit"]; ok {
		var r struct {
			Remaining int       `json:"remaining"`
			ResetAt   time.Time `json:"resetAt"`
		}
		if json.Unmarshal(rl, &r) == nil && r.Remaining < 50 {
			h.mu.Lock()
			h.waitTo["graphql"] = r.ResetAt.Add(2 * time.Second)
			h.mu.Unlock()
		}
	}
	res := map[string]*gqlRepo{}
	errs := map[string]string{}
	for _, e := range out.Errors {
		if len(e.Path) > 0 {
			if alias, ok := e.Path[0].(string); ok {
				var idx int
				if _, err := fmt.Sscanf(alias, "r%d", &idx); err == nil && idx < len(names) {
					if errs[names[idx]] == "" {
						errs[names[idx]] = e.Message
					}
				}
			}
		}
	}
	for i, n := range names {
		raw, ok := out.Data[fmt.Sprintf("r%d", i)]
		if !ok || string(raw) == "null" {
			if errs[n] == "" {
				errs[n] = "not found"
			}
			res[n] = nil
			continue
		}
		var gr gqlRepo
		if err := json.Unmarshal(raw, &gr); err != nil {
			errs[n] = err.Error()
			res[n] = nil
			continue
		}
		res[n] = &gr
	}
	return res, errs, nil
}

// PVR reports whether private vulnerability reporting is on. nil = unknown.
func (h *HTTP) PVR(ctx context.Context, fullName string) *bool {
	var out struct {
		Enabled bool `json:"enabled"`
	}
	code, err := h.GetJSON(ctx, "https://api.github.com/repos/"+fullName+"/private-vulnerability-reporting", &out)
	if err != nil || code != 200 {
		return nil
	}
	return &out.Enabled
}

// PublishedAdvisories counts published repository security advisories (GHSAs). -1 = unknown.
func (h *HTTP) PublishedAdvisories(ctx context.Context, fullName string) int {
	var out []struct {
		GhsaID string `json:"ghsa_id"`
	}
	code, err := h.GetJSON(ctx, "https://api.github.com/repos/"+fullName+"/security-advisories?state=published&per_page=100", &out)
	if err != nil || code != 200 {
		return -1
	}
	return len(out)
}

// DownloadToTemp streams url into a temp file, aborting past maxBytes.
func (h *HTTP) DownloadToTemp(ctx context.Context, rawURL, dir string, maxBytes int64) (string, int64, error) {
	resp, err := h.Do(ctx, "GET", rawURL, nil, "")
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("download: %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return "", 0, fmt.Errorf("archive is %d MB, over the %d MB limit", resp.ContentLength>>20, maxBytes>>20)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", 0, err
	}
	f, err := os.CreateTemp(dir, "dl-*.zip")
	if err != nil {
		return "", 0, err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1))
	f.Close()
	if err != nil {
		os.Remove(f.Name())
		return "", 0, err
	}
	if n > maxBytes {
		os.Remove(f.Name())
		return "", 0, fmt.Errorf("archive is over the %d MB limit", maxBytes>>20)
	}
	return f.Name(), n, nil
}
