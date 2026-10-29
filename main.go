package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

//go:embed web
var webFS embed.FS

//go:embed defaults
var defaultsFS embed.FS

const version = "0.1.0"

func main() {
	addr := flag.String("addr", "127.0.0.1:7777", "listen address (keep it on localhost)")
	dir := flag.String("dir", "", "base folder holding dorks/, sinks/ and data/ (default: current folder if it has dorks/, else the executable's folder)")
	noBrowser := flag.Bool("no-browser", false, "don't open the browser on start")
	flag.Parse()

	base := resolveBase(*dir)
	if err := loadDotEnv(filepath.Join(base, ".env")); err != nil {
		log.Printf("can't read .env: %v", err)
	}
	app, err := NewApp(base)
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("can't listen on %s: %v (try -addr 127.0.0.1:7778)", *addr, err)
	}
	url := "http://" + ln.Addr().String()
	log.Printf("sift %s running at %s", version, url)
	log.Printf("base folder: %s", base)
	log.Printf("drop dork files into %s", filepath.Join(base, "dorks"))
	if !*noBrowser {
		openBrowser(url)
	}
	if err := http.Serve(ln, app.Routes(sub)); err != nil {
		log.Fatal(err)
	}
}

// resolveBase picks the folder that holds dorks/, sinks/ and data/.
func resolveBase(flagDir string) string {
	if flagDir != "" {
		abs, _ := filepath.Abs(flagDir)
		return abs
	}
	if cwd, err := os.Getwd(); err == nil {
		if st, err := os.Stat(filepath.Join(cwd, "dorks")); err == nil && st.IsDir() {
			return cwd
		}
	}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		return filepath.Dir(exe)
	}
	cwd, _ := os.Getwd()
	return cwd
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
