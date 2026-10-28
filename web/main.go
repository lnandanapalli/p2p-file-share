// Static server for the browser client (share.nlpdf.site).
//
// Serves the files in site/ (built into the binary) with security headers.
// The relay address comes from RELAY_URL at startup, so the same image works
// with any relay: it is written into config.js and into the page's
// Content-Security-Policy (the only place, besides itself, that the page may
// connect to).
//
// Settings (environment variables):
//
//	WEB_ADDR   listen address (default :8080)
//	RELAY_URL  the relay, e.g. https://relay.nlpdf.site (the default)
package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

//go:embed site
var siteFS embed.FS

const defaultRelayURL = "https://relay.nlpdf.site"

type file struct {
	body  []byte
	ctype string
	etag  string
}

var relayLine = regexp.MustCompile(`(?m)^export const RELAY_URL = ".*";$`)

// relayFromEnv returns the relay base URL (no trailing slash) and its origin.
func relayFromEnv() (string, string, error) {
	raw := strings.TrimSpace(os.Getenv("RELAY_URL"))
	if raw == "" {
		raw = defaultRelayURL
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("RELAY_URL must look like https://relay.example.com, got %q", raw)
	}
	if u.Scheme != "https" {
		log.Printf("WARNING: RELAY_URL is not https; browsers on an https page will refuse to use it")
	}
	return u.String(), u.Scheme + "://" + u.Host, nil
}

// loadSite reads site/ into memory, with config.js pointing at relayURL.
func loadSite(relayURL string) (map[string]*file, error) {
	files := map[string]*file{}
	err := fs.WalkDir(siteFS, "site", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := siteFS.ReadFile(p)
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(p, "site")
		if name == "/config.js" {
			if !relayLine.Match(body) {
				return fmt.Errorf("config.js: RELAY_URL line not found")
			}
			body = relayLine.ReplaceAllLiteral(body, []byte(fmt.Sprintf("export const RELAY_URL = %q;", relayURL)))
		}
		ctype := mime.TypeByExtension(path.Ext(name))
		if ctype == "" {
			ctype = "application/octet-stream"
		}
		sum := sha256.Sum256(body)
		files[name] = &file{body: body, ctype: ctype, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
		return nil
	})
	return files, err
}

func securityHeaders(h http.Header, relayOrigin string) {
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
		"connect-src 'self' "+relayOrigin+"; worker-src blob:; img-src 'self' data:; object-src 'none'; "+
		"base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Strict-Transport-Security", "max-age=31536000")
}

func main() {
	addr := os.Getenv("WEB_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	relayURL, relayOrigin, err := relayFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	files, err := loadSite(relayURL)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		securityHeaders(h, relayOrigin)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Path
		if name == "/" {
			name = "/index.html"
		}
		f := files[name]
		if f == nil {
			http.NotFound(w, r)
			return
		}
		// Revalidate every time (cheap: ETag -> 304), so a new deployment is
		// picked up at once and the page never mixes old and new modules.
		h.Set("Content-Type", f.ctype)
		h.Set("ETag", f.etag)
		h.Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(f.body))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("web listening on %s (relay: %s)", addr, relayURL)
	log.Fatal(srv.ListenAndServe())
}
