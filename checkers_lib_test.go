package main

import (
	"archive/zip"
	"bytes"
	"testing"
)

func zipOf(t *testing.T, files map[string]string) []*zip.File {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, _ := zw.Create("repo-abc123/" + name)
		w.Write([]byte(body))
	}
	zw.Close()
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr.File
}

func TestLibraryLangs(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		js    bool
		py    bool
		golib bool
	}{
		{"npm library", map[string]string{"package.json": `{"name":"git-diff","main":"index.js"}`}, true, false, false},
		{"private app", map[string]string{"package.json": `{"name":"web","private":true,"main":"index.js"}`}, false, false, false},
		{"monorepo package", map[string]string{"package.json": `{"private":true}`, "packages/core/package.json": `{"name":"@x/core","exports":{".":"./dist/index.js"}}`}, true, false, false},
		{"python package", map[string]string{"pyproject.toml": "[project]\nname = \"rembg\"\n"}, false, true, false},
		{"python app with a Dockerfile", map[string]string{"pyproject.toml": "[project]\nname = \"raptor\"\n", "Dockerfile": "FROM python"}, false, false, false},
		{"go library", map[string]string{"go.mod": "module github.com/x/y", "zip.go": "package y"}, false, false, true},
		{"go app", map[string]string{"go.mod": "module github.com/x/y", "cmd/y/main.go": "package main"}, false, false, false},
	} {
		got := libraryLangs(zipOf(t, c.files), true)
		if got["js-ts"] != c.js || got["python"] != c.py || got["go"] != c.golib {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}
