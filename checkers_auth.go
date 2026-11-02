package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Routes that skip the auth their siblings have. When most routes in a file carry an auth
// middleware, dependency or decorator and one doesn't, that one was usually forgotten: the
// commonest shape of a missing-auth advisory in an app. Consistency is the signal, so a file
// with no auth anywhere (a public API, or auth done elsewhere) says nothing.

const routeAuthChecker = "route-auth-gap"

var (
	jsRouteRe = regexp.MustCompile("\\b([\\w$]+)\\.(get|post|put|patch|delete|all)\\(\\s*['\"`](/[^'\"`]*)['\"`]\\s*[,)]")
	pyRouteRe = regexp.MustCompile(`^\s*@\s*([\w.]+)\.(get|post|put|patch|delete|route|api_route)\(\s*[rf]?['"](/[^'"]*)['"]`)
	routeHint = regexp.MustCompile("\\.(get|post|put|patch|delete)\\(\\s*['\"`]/|@\\s*[\\w.]+\\.(get|post|put|patch|delete|route)\\(")

	// auth on the registration: middleware names, FastAPI dependencies, decorators
	authWordRe = regexp.MustCompile(`(?i)authenticat|authoriz|\b(is|ensure|check|verify|require|with|has)_?auth|auth_?(middleware|required|guard|check|user)|\bauth(ed|enticated)?\b|login_?required|logged_?in|\bjwt|bearer|require_?\w*token|\bSecurity\(|api_?key|current_?(user|account|admin)|get_current_\w+|require_?(user|admin|role|scope|login|session|permission)|is_?admin|admin_?(only|required)|permission|\bguard|protect|rbac|\bacl\b|oauth2_scheme|verify_?\w*token|token_?required`)
	// auth done inside the handler
	authBodyRe = regexp.MustCompile(`(?i)\breq(uest)?\.(user|auth|session\.user)\b|current_user|status(_code)?\s*[=(:]\s*40[13]\b|\b40[13]\b\s*[,)]|abort\(\s*40[13]|Unauthorized|Forbidden|isAuthenticated|getServerSession|auth\(\)|(require|verify|check)_?\w*token\(|\b_?(require|ensure|check|verify)_(admin|auth|user|login|role|permission)\w*\(`)
	// router-wide auth covers every route in the file
	jsRouterAuth = regexp.MustCompile(`\.use\(([^)]*)\)`)
	pyRouterAuth = regexp.MustCompile(`(?s)(APIRouter|FastAPI)\([^)]*dependencies\s*=\s*\[[^\]]*\]|add_middleware\(\s*\w*Auth|before_request`)

	publicPath     = regexp.MustCompile(`(?i)^/?$|/(redeem|exchange|refresh|token|login|logout|sign_?in|sign_?up|register|health\w*|healthz|status|ping|ready|live|public|callback|webhooks?|oauth\w*|auth\w*|static|assets|docs|openapi|swagger|redoc|version|metrics|favicon|robots|verify|reset|forgot|confirm|invite|\.well-known|captcha|csrf|session)\b`)
	sensitivePath  = regexp.MustCompile(`(?i)admin|config|settings|users?\b|accounts?|export|backup|secret|tokens?|keys?\b|logs?\b|debug|exec|run|command|files?|upload|download|delete|internal|system|env\b|database|db\b|shell|plugins?|install`)
	pyWriteMethods = regexp.MustCompile(`methods\s*=\s*\[[^\]]*['"](POST|PUT|PATCH|DELETE)['"]`)
	// an auth router mixes public and private routes on purpose: the login is public
	authRouteFile = regexp.MustCompile(`(?i)(auth|login|session|oauth|sso|account_?recovery)[^/]*$`)
	// HTTP clients look like routers: api.get("/users", { params })
	jsClientRecv = regexp.MustCompile(`^(axios|request|http|https|client|apiClient|fetcher|instance|\$http|got|ky|superagent|service|api)$`)
)

// ---------- catch-all proxies: the server's credential, for anyone ----------

const proxyChecker = "unprotected-proxy"

var (
	proxyPathJS    = regexp.MustCompile("\\.join\\(\\s*['\"`]/['\"`]\\s*\\)")
	proxyRawJS     = regexp.MustCompile(`\breq\.originalUrl\b|\breq\.params\[0\]`)
	proxyPathPy    = regexp.MustCompile(`\{\w+:path\}`)
	proxyForwardJS = regexp.MustCompile(`\b(fetch|axios(\.\w+)?|got)\(`)
	proxyForwardPy = regexp.MustCompile(`\b(httpx|requests|client|session)\.(get|post|put|patch|delete|request|stream)\(`)
	proxyHeader    = regexp.MustCompile("(?i)['\"`]?(x-[\\w-]*(key|token|secret|auth)[\\w-]*|authorization|api-?key)['\"`]?\\s*[:=]\\s*(.+)")
	proxyEnvJS     = regexp.MustCompile(`(?m)(?:const|let|var)\s+(\w+)\s*(?::[^=\n]+)?=\s*process\.env`)
	proxyEnvPy     = regexp.MustCompile(`(?m)^\s*(\w+)\s*(?::[^=\n]+)?=\s*(?:os\.environ|os\.getenv|settings\.)`)
	proxyEnvInline = regexp.MustCompile(`process\.env|os\.environ|os\.getenv|settings\.`)
	// narrower than authWordRe, where "api_key" would match the very header being added
	proxyLoginRe = regexp.MustCompile(`(?i)getServerSession|getSession|\bauth\(\)|verify\w*(session|token|user)|check\w*(session|auth|admin)|require\w*(auth|user|admin|login|session)|is_?authenticated|\breq(uest)?\.(user|session)\b|current_user|get_current_\w+|Depends\(\s*\w*(auth|user|admin)|session\.user|status:\s*40[13]|status_code\s*=\s*40[13]`)
)

// proxyHint is the cheap test for a file that may hold a catch-all proxy.
func proxyHint(name, src, lang string) bool {
	switch lang {
	case "js-ts":
		return strings.Contains(name, "[...") || strings.Contains(name, "[[...") || proxyRawJS.MatchString(src)
	case "python":
		return proxyPathPy.MatchString(src)
	}
	return false
}

// proxyAuthGaps flags handlers that forward any path upstream with a credential from the
// server's environment and check no login on the way.
func proxyAuthGaps(name, src string, lines []string, lang string, fns []fnSpan) []Finding {
	var env map[string]bool
	collect := func(re *regexp.Regexp) {
		env = map[string]bool{}
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			env[m[1]] = true
		}
	}
	nextRoute := strings.Contains(name, "[...") || strings.Contains(name, "[[...")
	forward := proxyForwardJS
	if lang == "python" {
		if pyRouterAuth.MatchString(src) {
			return nil
		}
		collect(proxyEnvPy)
		forward = proxyForwardPy
	} else {
		for _, m := range jsRouterAuth.FindAllStringSubmatch(src, -1) {
			if authWordRe.MatchString(m[1]) {
				return nil
			}
		}
		collect(proxyEnvJS)
	}
	sorted := append([]fnSpan(nil), fns...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].start < sorted[j].start })
	var out []Finding
	covered := -1
	for _, f := range sorted {
		if f.start <= covered || f.end < f.start || f.end >= len(lines) || f.head >= len(lines) {
			continue
		}
		body := strings.Join(lines[f.head:f.end+1], "\n")
		if !forward.MatchString(body) {
			continue
		}
		catchAll := false
		if lang == "python" {
			for j := f.head - 1; j >= 0 && strings.HasPrefix(strings.TrimSpace(lines[j]), "@"); j-- {
				catchAll = catchAll || proxyPathPy.MatchString(lines[j])
			}
		} else {
			catchAll = nextRoute && proxyPathJS.MatchString(body) || proxyRawJS.MatchString(body)
		}
		if !catchAll || proxyLoginRe.MatchString(body) {
			continue
		}
		cred := ""
		for _, m := range proxyHeader.FindAllStringSubmatch(body, -1) {
			if proxyEnvInline.MatchString(m[3]) || mentionsName(m[3], env) {
				cred = m[1]
				break
			}
		}
		if cred == "" {
			continue
		}
		covered = f.end
		out = append(out, Finding{Checker: proxyChecker, Class: "missing-auth", Path: name, Line: f.head + 1, Func: f.name,
			Message: "Catch-all proxy forwards any path upstream with the server's own credential (" + cred + ") and checks no login in the handler. Anyone who can reach it acts with that credential, unless a middleware file covers the route",
			Snippet: strings.TrimSpace(lines[f.head]), Confidence: "medium", Weight: 3.5})
	}
	return out
}

type route struct {
	line          int
	method, path  string
	fn            string
	authed, write bool
}

func routeAuthGaps(name, src string, lines []string, lang string, fns []fnSpan) []Finding {
	if authRouteFile.MatchString(strings.TrimSuffix(name, path.Ext(name))) {
		return nil
	}
	var routes []route
	byHead := map[int]fnSpan{}
	for _, f := range fns {
		byHead[f.head] = f
	}
	body := func(f fnSpan) string {
		if f.end < f.start || f.end >= len(lines) {
			return ""
		}
		return strings.Join(lines[f.start:min(f.end, f.start+25)+1], "\n")
	}
	switch lang {
	case "js-ts":
		for _, m := range jsRouterAuth.FindAllStringSubmatch(src, -1) {
			if authWordRe.MatchString(m[1]) {
				return nil
			}
		}
		starts := lineStarts(src)
		for _, m := range jsRouteRe.FindAllStringSubmatchIndex(src, -1) {
			l := lineOf(starts, m[0])
			if commentLine(lines[l], lang) {
				continue
			}
			before := strings.TrimSpace(src[strings.LastIndexByte(src[:m[0]], '\n')+1 : m[0]])
			after := strings.TrimSpace(src[m[1]-1 : min(len(src), m[1]+40)])
			if jsClientRecv.MatchString(src[m[2]:m[3]]) || strings.HasSuffix(before, "await") || strings.HasSuffix(before, "return") ||
				strings.HasSuffix(before, "=") || strings.HasPrefix(after, ",{") || strings.HasPrefix(after, ", {") || strings.HasPrefix(after, ")") {
				continue // a client call, not a route: no handler follows the path
			}
			// the middleware sit between the path and the handler
			region := src[m[1]:min(len(src), m[1]+400)]
			if i := strings.Index(region, "=>"); i >= 0 {
				region = region[:i]
			}
			if i := strings.Index(region, "function"); i >= 0 {
				region = region[:i]
			}
			r := route{line: l, method: strings.ToUpper(src[m[4]:m[5]]), path: src[m[6]:m[7]]}
			r.write = r.method != "GET"
			r.authed = authWordRe.MatchString(region)
			for h := l; h <= min(l+3, len(lines)-1) && !r.authed; h++ {
				if f, ok := byHead[h]; ok {
					r.fn = f.name
					r.authed = authBodyRe.MatchString(body(f))
				}
			}
			routes = append(routes, r)
		}
	case "python":
		if pyRouterAuth.MatchString(src) {
			return nil
		}
		for i, line := range lines {
			m := pyRouteRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			r := route{line: i, method: strings.ToUpper(m[2]), path: m[3]}
			// the whole decorator stack, then the def and its parameters
			j := i
			for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "def ") && !strings.HasPrefix(strings.TrimSpace(lines[j]), "async def ") && j < i+12 {
				j++
			}
			k := i
			for k > 0 && strings.HasPrefix(strings.TrimSpace(lines[k-1]), "@") {
				k--
			}
			deco := strings.Join(lines[k:min(j, len(lines))], "\n")
			r.write = r.method == "POST" || r.method == "PUT" || r.method == "PATCH" || r.method == "DELETE" || pyWriteMethods.MatchString(deco)
			if r.method == "ROUTE" || r.method == "API_ROUTE" {
				r.method = "GET"
				if r.write {
					r.method = "POST"
				}
			}
			r.authed = authWordRe.MatchString(deco)
			if f, ok := byHead[j]; ok && !r.authed {
				r.fn = f.name
				sig := strings.Join(lines[j:min(f.start+1, len(lines))], " ")
				r.authed = authWordRe.MatchString(sig) || authBodyRe.MatchString(body(f))
			}
			routes = append(routes, r)
		}
	}
	authed := 0
	for _, r := range routes {
		if r.authed {
			authed++
		}
	}
	if len(routes) < 3 || authed < 2 || authed*2 < len(routes) {
		return nil
	}
	var out []Finding
	for _, r := range routes {
		if r.authed || publicPath.MatchString(r.path) || !r.write && !sensitivePath.MatchString(r.path) {
			continue
		}
		out = append(out, Finding{Checker: routeAuthChecker, Class: "missing-auth", Path: name, Line: r.line + 1, Func: r.fn,
			Message:    fmt.Sprintf("%s %s has no auth check, while %d of the %d routes in this file have one", r.method, r.path, authed, len(routes)),
			Snippet:    strings.TrimSpace(lines[r.line]),
			Confidence: "medium", Weight: 3})
	}
	return out
}
