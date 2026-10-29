package main

import (
	"bytes"
	"regexp/syntax"
	"sort"
	"strings"
)

// Regex scanning dominates scan time, and most patterns can't match most files: a file with no
// "exec" in it has no exec-style call. requiredLits works out, from a pattern's syntax tree, a
// set of lowercase literals such that every match contains at least one of them. Callers look
// for those with a plain substring search first and only run the regex on lines that have one.

const minLitLen = 3 // shorter literals ("fs", "<") filter too little to be worth it

// requiredLits returns the literal set for pattern, or nil when no useful set exists.
func requiredLits(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	lits := litsOf(re.Simplify())
	for _, l := range lits {
		if len(l) < minLitLen || !isASCII(l) {
			return nil // text is lowercased ASCII-only, so non-ASCII literals can't be matched reliably
		}
	}
	return lits
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// asciiLower lowercases A-Z only. Unlike bytes.ToLower it never changes the length (some
// Unicode letters lowercase to more or fewer bytes, and invalid UTF-8 gets replaced), so
// offsets in the result line up with the original.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func litsOf(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(re.Rune))}
	case syntax.OpCapture:
		return litsOf(re.Sub[0])
	case syntax.OpPlus:
		return litsOf(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return litsOf(re.Sub[0])
		}
	case syntax.OpConcat:
		// any child's requirement holds for the whole; keep the most selective one, and join
		// runs of adjacent literals ("fs" "." "readFile") into one longer literal
		var best []string
		run := ""
		consider := func(set []string) {
			if set != nil && (best == nil || shortest(set) > shortest(best)) {
				best = set
			}
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				run += strings.ToLower(string(sub.Rune))
				continue
			}
			if run != "" {
				consider([]string{run})
				run = ""
			}
			consider(litsOf(sub))
		}
		if run != "" {
			consider([]string{run})
		}
		return best
	case syntax.OpAlternate:
		var all []string
		for _, sub := range re.Sub {
			set := litsOf(sub)
			if set == nil {
				return nil // one branch needs nothing in particular
			}
			all = append(all, set...)
		}
		return all
	}
	return nil
}

func shortest(set []string) int {
	n := -1
	for _, s := range set {
		if n < 0 || len(s) < n {
			n = len(s)
		}
	}
	return n
}

// litLines returns the sorted line indexes of lower (a lowercased file) that contain any of lits.
func litLines(lower []byte, starts []int, lits []string) []int {
	seen := map[int]bool{}
	var out []int
	for _, l := range lits {
		lb := []byte(l)
		for off := 0; ; {
			i := bytes.Index(lower[off:], lb)
			if i < 0 {
				break
			}
			line := lineOf(starts, off+i)
			if !seen[line] {
				seen[line] = true
				out = append(out, line)
			}
			// skip to the next line: one hit per line is enough
			if line+1 < len(starts) {
				off = starts[line+1]
			} else {
				break
			}
		}
	}
	sort.Ints(out)
	return out
}

func containsAnyLit(lower string, lits []string) bool {
	for _, l := range lits {
		if strings.Contains(lower, l) {
			return true
		}
	}
	return false
}
