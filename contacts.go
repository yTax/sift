package main

import (
	"regexp"
	"sort"
	"strings"
)

var (
	emailRe    = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b`)
	discordRe  = regexp.MustCompile(`(?i)\b(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/[a-z0-9\-]{2,}`)
	discordURe = regexp.MustCompile(`(?i)\b(?:https?://)?(?:www\.)?discord(?:app)?\.com/users/\d{5,}`)
	telegramRe = regexp.MustCompile(`(?i)\b(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/(?:\+|joinchat/)?[a-z0-9_]{3,}`)
	twitterRe  = regexp.MustCompile(`(?i)\b(?:https?://)?(?:www\.|mobile\.)?(?:twitter|x)\.com/([a-z0-9_]{1,15})\b`)
	matrixRe   = regexp.MustCompile(`(?i)\bmatrix\.to/#/[@#!][^\s)\]"'<>]+`)
	blueskyRe  = regexp.MustCompile(`(?i)\bbsky\.app/profile/[a-z0-9.\-:]+`)
	mastodonRe = regexp.MustCompile(`(?i)\bhttps?://[a-z0-9.\-]+/@[a-z0-9_]{2,}\b`)
)

var twitterReserved = map[string]bool{"intent": true, "share": true, "home": true, "search": true, "hashtag": true, "i": true, "login": true, "signup": true, "settings": true, "explore": true, "messages": true, "notifications": true}

// Junk is checked per part so "poweruser@x.dev" or "contest@x.dev" survive while "user@x.dev" doesn't.
var (
	emailJunkLocal = map[string]bool{
		"user": true, "test": true, "foo": true, "bar": true, "email": true, "name": true, "you": true,
		"your": true, "yourname": true, "your-email": true, "youremail": true, "example": true, "me": true,
		"someone": true, // note: admin@/security@ are deliberately NOT junk — they're often the real contact
	}
	emailJunkDomain = []string{
		"users.noreply.github.com", "example.com", "example.org", "example.net", "domain.com", "email.com",
		"yourdomain", "sentry.io", "localhost", "wixpress.com", "godaddy.com", "github.com", "test.com",
	}
	emailJunkAny = []string{"noreply", "no-reply", "donotreply"}
	// "logo@2x.png", "@types/node", "@babel/core" etc. look like emails to the regex
	emailJunkTLD = map[string]bool{"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "webp": true, "js": true, "ts": true, "css": true}
)

func cleanEmail(e string) (string, bool) {
	e = strings.ToLower(strings.Trim(e, ".-_"))
	local, domain, ok := strings.Cut(e, "@")
	if !ok || strings.Contains(domain, "@") || local == "" || domain == "" {
		return "", false
	}
	if emailJunkLocal[local] {
		return "", false
	}
	for _, j := range emailJunkAny {
		if strings.Contains(e, j) {
			return "", false
		}
	}
	for _, j := range emailJunkDomain {
		if strings.Contains(domain, j) {
			return "", false
		}
	}
	if i := strings.LastIndexByte(domain, '.'); i >= 0 && emailJunkTLD[domain[i+1:]] {
		return "", false
	}
	if strings.HasPrefix(domain, "2x.") || strings.HasPrefix(domain, "3x.") {
		return "", false
	}
	return e, true
}

func normURL(u string) string {
	u = strings.TrimRight(u, ".,);:]>\"'`")
	if !strings.HasPrefix(strings.ToLower(u), "http") {
		u = "https://" + u
	}
	return u
}

type contactSet struct {
	list []Contact
	seen map[string]bool
}

func (cs *contactSet) add(kind, value, link, where string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	k := kind + "|" + strings.ToLower(value)
	if cs.seen == nil {
		cs.seen = map[string]bool{}
	}
	if cs.seen[k] {
		return
	}
	cs.seen[k] = true
	cs.list = append(cs.list, Contact{Kind: kind, Value: value, URL: link, Where: where})
}

// scanText pulls every contact handle out of free text.
func (cs *contactSet) scanText(text, where string) {
	if text == "" {
		return
	}
	if len(text) > 400_000 {
		text = text[:400_000]
	}
	for _, m := range emailRe.FindAllString(text, 40) {
		if e, ok := cleanEmail(m); ok {
			cs.add("email", e, "mailto:"+e, where)
		}
	}
	for _, m := range discordRe.FindAllString(text, 20) {
		u := normURL(m)
		cs.add("discord", strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://"), u, where)
	}
	for _, m := range discordURe.FindAllString(text, 10) {
		u := normURL(m)
		cs.add("discord", strings.TrimPrefix(u, "https://"), u, where)
	}
	for _, m := range telegramRe.FindAllString(text, 20) {
		if strings.Contains(strings.ToLower(m), "/share") {
			continue
		}
		u := normURL(m)
		cs.add("telegram", strings.TrimPrefix(u, "https://"), u, where)
	}
	for _, m := range twitterRe.FindAllStringSubmatch(text, 20) {
		if twitterReserved[strings.ToLower(m[1])] {
			continue
		}
		cs.add("twitter", "@"+m[1], "https://x.com/"+m[1], where)
	}
	for _, m := range matrixRe.FindAllString(text, 10) {
		u := normURL(m)
		cs.add("matrix", strings.TrimPrefix(u, "https://"), u, where)
	}
	for _, m := range blueskyRe.FindAllString(text, 10) {
		u := normURL(m)
		cs.add("bluesky", strings.TrimPrefix(u, "https://"), u, where)
	}
	for _, m := range mastodonRe.FindAllString(text, 10) {
		lm := strings.ToLower(m)
		if strings.Contains(lm, "medium.com") || strings.Contains(lm, "youtube.com") || strings.Contains(lm, "npmjs.com") || strings.Contains(lm, "tiktok.com") {
			continue
		}
		cs.add("mastodon", strings.TrimPrefix(m, "https://"), m, where)
	}
}

var contactRank = map[string]int{
	"pvr": 0, "security_policy": 1, "email": 2, "discord": 3, "telegram": 4, "matrix": 5,
	"twitter": 6, "bluesky": 7, "mastodon": 8, "website": 9, "profile": 10,
}

func sortContacts(list []Contact) {
	sort.SliceStable(list, func(i, j int) bool {
		ri, ok := contactRank[list[i].Kind]
		if !ok {
			ri = 99
		}
		rj, ok := contactRank[list[j].Kind]
		if !ok {
			rj = 99
		}
		return ri < rj
	})
}

// contactsFromGitHub builds the contact list from enrichment data.
func contactsFromGitHub(g *gqlRepo, pvr *bool) []Contact {
	var cs contactSet
	full := g.NameWithOwner
	if pvr != nil && *pvr {
		u := "https://github.com/" + full + "/security/advisories/new"
		cs.add("pvr", "Private vulnerability reporting", u, "repo settings")
	}
	if g.IsSecurityPolicyEnabled {
		u := str(g.SecurityPolicyURL)
		if u == "" {
			u = "https://github.com/" + full + "/security/policy"
		}
		cs.add("security_policy", "Security policy", u, "SECURITY.md")
	}
	cs.scanText(g.security(), "SECURITY.md")
	cs.scanText(g.readme(), "README")
	if g.Funding != nil && g.Funding.Text != nil {
		cs.scanText(*g.Funding.Text, "FUNDING.yml")
	}
	o := g.Owner
	if e := str(o.Email); e != "" {
		if ce, ok := cleanEmail(e); ok {
			cs.add("email", ce, "mailto:"+ce, "owner profile")
		}
	}
	if t := str(o.TwitterUsername); t != "" {
		cs.add("twitter", "@"+t, "https://x.com/"+t, "owner profile")
	}
	if o.SocialAccounts != nil {
		for _, sa := range o.SocialAccounts.Nodes {
			before := len(cs.list)
			cs.scanText(sa.URL, "owner profile")
			if len(cs.list) == before && sa.URL != "" {
				cs.add("website", sa.URL, sa.URL, "owner profile ("+strings.ToLower(sa.Provider)+")")
			}
		}
	}
	cs.scanText(str(o.Bio)+"\n"+str(o.Description)+"\n"+str(o.Company), "owner profile")
	if w := str(o.WebsiteURL); w != "" {
		before := len(cs.list)
		cs.scanText(w, "owner profile")
		if len(cs.list) == before {
			cs.add("website", w, normURL(w), "owner profile")
		}
	}
	if h := str(g.HomepageURL); h != "" {
		cs.add("website", h, normURL(h), "repo homepage")
	}
	cs.add("profile", "@"+o.Login, o.URL, "GitHub")
	sortContacts(cs.list)
	return cs.list
}

// hasQualifyingContact checks whether any contact kind counts toward "has a contact".
func hasQualifyingContact(list []Contact, kinds []string) bool {
	ok := map[string]bool{}
	for _, k := range kinds {
		ok[k] = true
	}
	for _, c := range list {
		if ok[c.Kind] {
			return true
		}
	}
	return false
}
