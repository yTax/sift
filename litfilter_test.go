package main

import (
	"strings"
	"testing"
)

func TestRequiredLits(t *testing.T) {
	cases := []struct {
		pattern string
		want    string // sorted, comma-joined; "" = no shortcut
	}{
		{`(child_process|childProcess|cp)\.(exec|execSync|spawn)\(`, "exec,spawn"}, // the cp branch is too short, so the call names win
		{`\b(fs|fsp)\.(readFile|writeFile)\(`, "readfile,writefile"},
		{`(?i)\bselect\s+\*`, "select"},
		{`\.innerHTML\s*=|insertAdjacentHTML\(`, ".innerhtml,insertadjacenthtml("},
		{`eval\(|x`, ""}, // one branch needs nothing
		{`\bfs\.\w+\(`, "fs."},
		{`naïve\(`, ""}, // non-ASCII literals are skipped
	}
	for _, c := range cases {
		got := requiredLits(c.pattern)
		sortStrings(got)
		if g := strings.Join(got, ","); g != c.want {
			t.Errorf("%s: got %q, want %q", c.pattern, g, c.want)
		}
	}
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// A file whose lowercase form has a different byte length (here a Turkish dotted capital I)
// must not knock the line offsets out of range.
func TestLitLinesNonASCII(t *testing.T) {
	src := []byte("// İstanbul İİİİ\nconst x = 1\nexec(cmd)\n")
	f := fileBytes{b: src, lower: asciiLower(src), starts: lineStartsBytes(src)}
	if len(f.lower) != len(f.b) {
		t.Fatalf("asciiLower changed the length")
	}
	got := litLines(f.lower, f.starts, []string{"exec"})
	if len(got) != 1 || got[0] != 2 {
		t.Errorf("lines = %v, want [2]", got)
	}
}

func TestSafeScanZipRecovers(t *testing.T) {
	_, err := safeScanZip("does-not-exist.zip", scanOpts{})
	if err == nil {
		t.Error("expected an error for a missing archive")
	}
}
