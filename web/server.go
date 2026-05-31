// Package web is the LinAudit dashboard HTTP server. It binds 127.0.0.1 only,
// gates every data/control endpoint behind a password-derived session cookie and
// a per-process CSRF token, and serves a single embedded dashboard page plus the
// network/process/status/log/report JSON APIs.
//
// Security model (ported from server.py):
//   - binds 127.0.0.1 only (never a routable interface)
//   - first run: SETUP page sets a password (scrypt-hashed, /var/lib/linaudit/auth.json 0600)
//   - login issues an in-memory session token delivered as an HttpOnly,
//     SameSite=Strict cookie; all data/control endpoints require a valid session
//   - a per-start CSRF token is embedded only in the same-origin dashboard HTML
//     and required on /api/* (a cross-origin page cannot read it)
//   - Host header allowlist defeats DNS-rebinding; Origin / Sec-Fetch-Site checked
//   - no static file serving; subprocess calls use fixed argument arrays (no shell)
package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"linaudit/identity"
	"linaudit/web/netmon"
	"linaudit/web/procmon"
)

// Network identity. PORT is fixed; the listen address may be overridden via
// LINAUDIT_ADDR for testing but the host allowlists always include both the
// loopback IP and "localhost" forms on PORT.
const (
	host = "127.0.0.1"
	port = 8799
)

// Service unit names toggled by the dashboard.
const (
	inputService = "linaudit-input.service"
	auditService = "auditd.service"
)

// geoDir is where the offline GeoIP CSVs live; netmon loads them at start.
const geoDir = "/usr/local/share/linaudit/geoip"

// mnt is the encrypted store mount point used for the "encrypted" status flag.
const mnt = "/var/log/linaudit"

// authFile is the on-disk password record (writable under ProtectSystem=full).
const authFile = "/var/lib/linaudit/auth.json"

// keyLog is the keystroke log (a symlink into the encrypted store).
const keyLog = "/var/log/linaudit/input/keys.log"

// Identity and per-user paths, resolved once at package init from os/user with
// env and literal fallbacks, exactly as the spec prescribes.
var (
	linauditUser string
	homeDir      string
	zdir         string
	bufLog       string
	cmdLog       string
	disFlag      string
)

func init() {
	// Detect the monitored account from the environment + system (see the
	// identity package). On a host with no resolvable user, homeDir is "" and the
	// per-user (zsh) paths stay empty -- zshOn()/logmeta() then report the layer
	// off / zero rather than reading a bogus /home/<literal> path.
	linauditUser = identity.User()
	homeDir = identity.Home()
	if homeDir != "" {
		zdir = homeDir + "/.local/share/linaudit"
		bufLog = zdir + "/buffer.log"
		cmdLog = zdir + "/commands.log"
		disFlag = zdir + "/disabled"
	}
}

// allowedHosts / allowedOrigins guard against DNS-rebinding and cross-origin use.
var (
	allowedHosts = map[string]bool{
		host + ":" + strconv.Itoa(port):   true,
		"localhost:" + strconv.Itoa(port): true,
	}
	allowedOrigins = map[string]bool{
		"http://" + host + ":" + strconv.Itoa(port): true,
		"http://localhost:" + strconv.Itoa(port):    true,
	}
)

// server holds the per-process CSRF token, the session table, and the login
// throttle. One instance is created in Run().
type server struct {
	token    string
	sessions *sessionStore

	failMu    sync.Mutex
	failCount int
	failUntil time.Time
}

// newServer mints the per-start CSRF token (32 random bytes -> RawURLEncoding).
func newServer() (*server, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return &server{
		token:    base64.RawURLEncoding.EncodeToString(raw),
		sessions: newSessionStore(),
	}, nil
}

// Run starts the background samplers and serves the dashboard. It blocks until
// the HTTP server returns (only on error).
func Run() error {
	netmon.Start(geoDir, true)
	procmon.Start()

	s, err := newServer()
	if err != nil {
		return err
	}

	addr := os.Getenv("LINAUDIT_ADDR")
	if addr == "" {
		addr = host + ":" + strconv.Itoa(port)
	}

	srv := &http.Server{Addr: addr, Handler: s}
	return srv.ListenAndServe()
}

// ServeHTTP is the single entry point; it dispatches by method.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGet(w, r)
	case http.MethodPost:
		s.handlePost(w, r)
	default:
		s.send(w, http.StatusNotFound, "text/plain", []byte("not found"), "")
	}
}

// ----------------------------- request checks ------------------------------

// okOrigin enforces the Host allowlist plus Origin / Sec-Fetch-Site checks.
func okOrigin(r *http.Request) bool {
	if !allowedHosts[r.Host] {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" && !allowedOrigins[origin] {
		return false
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		return false
	}
	return true
}

// tokenOK constant-time compares the X-Audit-Token header with the CSRF token.
func (s *server) tokenOK(r *http.Request) bool {
	got := r.Header.Get("X-Audit-Token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// cookieSession extracts the audit_session cookie value, or "" if absent.
func cookieSession(r *http.Request) string {
	c, err := r.Cookie("audit_session")
	if err != nil {
		return ""
	}
	return c.Value
}

// authed reports whether the request carries a valid session cookie.
func (s *server) authed(r *http.Request) bool {
	return s.sessions.ok(cookieSession(r))
}

// readBody reads and JSON-decodes the request body into a generic map. It
// returns (nil, true) when the body is not valid JSON (Python's "bad json"),
// and (map, false) on success (an empty body decodes to {}).
func readBody(r *http.Request) (map[string]any, bool) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, true
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return map[string]any{}, false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
		return nil, true
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, false
}

// ----------------------------- response helpers ----------------------------

// send writes a response with the standard hardening headers. cookie, if
// non-empty, is set as Set-Cookie.
func (s *server) send(w http.ResponseWriter, code int, ctype string, body []byte, cookie string) {
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if cookie != "" {
		h.Set("Set-Cookie", cookie)
	}
	w.WriteHeader(code)
	w.Write(body)
}

// sendText is a convenience for plain-text responses.
func (s *server) sendText(w http.ResponseWriter, code int, body string) {
	s.send(w, code, "text/plain", []byte(body), "")
}

// sendJSON marshals obj and writes it as application/json. cookie, if non-empty,
// is set. A marshal failure degrades to a 500 (it should never happen for our
// concrete payload types).
func (s *server) sendJSON(w http.ResponseWriter, code int, obj any, cookie string) {
	blob, err := json.Marshal(obj)
	if err != nil {
		s.sendText(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.send(w, code, "application/json", blob, cookie)
}

// ------------------------------ GET routing --------------------------------

func (s *server) handleGet(w http.ResponseWriter, r *http.Request) {
	if !okOrigin(r) {
		s.sendText(w, http.StatusForbidden, "forbidden")
		return
	}
	path := r.URL.Path

	if path == "/" || path == "/index.html" {
		if loadAuth() == nil {
			s.send(w, http.StatusOK, "text/html; charset=utf-8", []byte(setupPage), "")
			return
		}
		if !s.authed(r) {
			s.send(w, http.StatusOK, "text/html; charset=utf-8", []byte(loginPage), "")
			return
		}
		html := strings.Replace(DashboardHTML, "__TOKEN__", s.token, 1)
		s.send(w, http.StatusOK, "text/html; charset=utf-8", []byte(html), "")
		return
	}

	if strings.HasPrefix(path, "/api/") || path == "/world.svg" {
		if !s.authed(r) {
			s.sendText(w, http.StatusUnauthorized, "auth required")
			return
		}
		if !s.tokenOK(r) {
			s.sendText(w, http.StatusUnauthorized, "bad token")
			return
		}
		switch path {
		case "/world.svg":
			s.send(w, http.StatusOK, "image/svg+xml", WorldSVG, "")
		case "/api/net":
			s.sendJSON(w, http.StatusOK, netmon.SnapshotJSON(), "")
		case "/api/proc":
			s.sendJSON(w, http.StatusOK, procmon.SnapshotJSON(), "")
		case "/api/status":
			s.sendJSON(w, http.StatusOK, status(), "")
		case "/api/log":
			which := queryDefault(r, "which", "buffer")
			n := clamp(queryInt(r, "lines", 200), 1, 5000)
			s.sendJSON(w, http.StatusOK, map[string]any{
				"which": which,
				"lines": logview(which, n),
			}, "")
		case "/api/report":
			n := clamp(queryInt(r, "n", 25), 1, 200)
			s.sendJSON(w, http.StatusOK, map[string]any{
				"items": report(n),
			}, "")
		default:
			s.sendText(w, http.StatusNotFound, "not found")
		}
		return
	}

	s.sendText(w, http.StatusNotFound, "not found")
}

// ------------------------------ POST routing -------------------------------

func (s *server) handlePost(w http.ResponseWriter, r *http.Request) {
	if !okOrigin(r) {
		s.sendText(w, http.StatusForbidden, "forbidden")
		return
	}
	body, bad := readBody(r)
	if bad {
		s.sendText(w, http.StatusBadRequest, "bad json")
		return
	}
	path := r.URL.Path

	switch path {
	case "/api/setup":
		s.handleSetup(w, body)
		return
	case "/api/login":
		s.handleLogin(w, body)
		return
	}

	// Everything below requires an authenticated session.
	if !s.authed(r) {
		s.sendText(w, http.StatusUnauthorized, "auth required")
		return
	}

	switch path {
	case "/api/logout":
		s.sessions.drop(cookieSession(r))
		s.sendJSON(w, http.StatusOK, map[string]any{"ok": true}, sessionCookie("", true))
	case "/api/toggle":
		if !s.tokenOK(r) {
			s.sendText(w, http.StatusUnauthorized, "bad token")
			return
		}
		layer, _ := body["layer"].(string)
		action, _ := body["action"].(string)
		if !validLayer(layer) || (action != "enable" && action != "disable") {
			s.sendText(w, http.StatusBadRequest, "bad params")
			return
		}
		s.sendJSON(w, http.StatusOK, toggle(layer, action), "")
	default:
		s.sendText(w, http.StatusNotFound, "not found")
	}
}

// handleSetup performs first-run password configuration.
func (s *server) handleSetup(w http.ResponseWriter, body map[string]any) {
	if loadAuth() != nil {
		s.sendText(w, http.StatusForbidden, "already configured")
		return
	}
	pw, ok := body["password"].(string)
	if !ok || len(pw) < 8 {
		s.sendText(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if err := saveAuth(pw); err != nil {
		s.sendText(w, http.StatusInternalServerError, "could not save password")
		return
	}
	s.issueSession(w)
}

// handleLogin verifies a password with the crude throttle ported from server.py.
func (s *server) handleLogin(w http.ResponseWriter, body map[string]any) {
	now := time.Now()

	s.failMu.Lock()
	if now.Before(s.failUntil) {
		s.failMu.Unlock()
		s.sendText(w, http.StatusTooManyRequests, "too many attempts, wait a moment")
		return
	}
	s.failMu.Unlock()

	pw, _ := body["password"].(string)
	if verifyPw(pw) {
		s.failMu.Lock()
		s.failCount = 0
		s.failMu.Unlock()
		s.issueSession(w)
		return
	}

	// Failed attempt: increment, deliberately sleep, and lock out after 5.
	s.failMu.Lock()
	s.failCount++
	s.failMu.Unlock()

	time.Sleep(500 * time.Millisecond)

	s.failMu.Lock()
	if s.failCount >= 5 {
		s.failUntil = now.Add(30 * time.Second)
		s.failCount = 0
	}
	s.failMu.Unlock()

	s.sendText(w, http.StatusUnauthorized, "invalid password")
}

// issueSession mints a session and returns {ok:true} with the session cookie.
func (s *server) issueSession(w http.ResponseWriter) {
	tok, err := s.sessions.create()
	if err != nil {
		s.sendText(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.sendJSON(w, http.StatusOK, map[string]any{"ok": true}, sessionCookie(tok, false))
}

// ------------------------------ small helpers ------------------------------

// validLayer reports whether layer is one of the toggleable layers.
func validLayer(layer string) bool {
	return layer == "zsh" || layer == "input" || layer == "audit"
}

// queryDefault returns the named query parameter or def when missing/empty.
func queryDefault(r *http.Request, key, def string) string {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	return v
}

// queryInt parses the named query parameter as an int, returning def on
// missing/empty/unparseable input (mirroring Python's `or default` fallback).
func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// clamp constrains v to [lo, hi].
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
