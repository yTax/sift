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
	"strings"
	"time"
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
	allowHost := flag.String("allow-host", "", "extra host names/IPs the UI may be reached on, comma-separated (e.g. your Tailscale IP); sift has no login, so only use addresses on a private network")
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
	var extra []string
	if *allowHost != "" {
		extra = strings.Split(*allowHost, ",")
		log.Printf("also answering as: %s", *allowHost)
	}
	srv := &http.Server{
		Handler:           app.Routes(sub, extra...),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if err := srv.Serve(ln); err != nil {
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
