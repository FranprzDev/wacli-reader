package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var chatRe = regexp.MustCompile(`^[A-Za-z0-9+][A-Za-z0-9@._+ -]{0,63}$`)
var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
var phoneRe = regexp.MustCompile(`^\d{8,15}$`)

// v0.26.0 internal/out/events.go and cmd/wacli/auth.go define this contract.
// Only qr_code events are retained; all other lifecycle and bootstrap data is discarded.
func qrEvent(line string) string {
	var e struct {
		Event string `json:"event"`
		Data  struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(line), &e) != nil || e.Event != "qr_code" {
		return ""
	}
	code := e.Data.Code
	if len(code) < 7 || len(code) > 2048 || !strings.HasPrefix(code, "2@") {
		return ""
	}
	for _, c := range code[2:] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("+/=,-_", c)) {
			return ""
		}
	}
	return code
}

type account struct {
	Authenticated bool   `json:"authenticated"`
	Phone         string `json:"phone"`
}
type envelope struct {
	Success bool    `json:"success"`
	Data    account `json:"data"`
}
type server struct {
	token, store, bin, phone string
	days, maxChat            int
	mu                       sync.Mutex
	busy, state, qr          string
	authTimeout, syncTimeout time.Duration
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func (s *server) cmd(ctx context.Context, ro bool, args ...string) *exec.Cmd {
	full := []string{"--store", s.store}
	if ro {
		full = append(full, "--read-only")
	}
	full = append(full, args...)
	c := exec.CommandContext(ctx, s.bin, full...)
	c.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp", "WACLI_SYNC_MAX_MESSAGES=10000", "WACLI_SYNC_MAX_DB_SIZE=200MB"}
	return c
}
func (s *server) account(ctx context.Context) (account, error) {
	out, err := s.cmd(ctx, true, "--json", "auth", "status").Output()
	if err != nil {
		return account{}, err
	}
	var e envelope
	if json.Unmarshal(out, &e) != nil || !e.Success {
		return account{}, errors.New("invalid status")
	}
	return e.Data, nil
}
func (s *server) match(a account) bool {
	return a.Authenticated && a.Phone == s.phone && phoneRe.MatchString(s.phone)
}
func (s *server) status() (account, error) {
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	return s.account(ctx)
}
func (s *server) wrap(method string, needsAccount bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(s.token) < 32 || len(got) != len(s.token) || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != method {
			http.Error(w, "method not allowed", 405)
			return
		}
		if needsAccount {
			a, e := s.status()
			if e != nil || !s.match(a) {
				http.Error(w, "account not verified", 403)
				return
			}
		}
		h(w, r)
	}
}
func (s *server) begin(kind string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy != "" {
		return false
	}
	s.busy = kind
	s.qr = ""
	s.state = kind
	return true
}
func (s *server) end(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.busy = ""
	s.qr = ""
	s.state = state
}
func intParam(r *http.Request, k string, d, max int) (int, bool) {
	v := r.URL.Query().Get(k)
	if v == "" {
		return d, true
	}
	n, e := strconv.Atoi(v)
	return n, e == nil && n > 0 && n <= max
}
func common(r *http.Request, args []string) ([]string, bool) {
	if c := r.URL.Query().Get("chat"); c != "" {
		if !chatRe.MatchString(c) {
			return nil, false
		}
		args = append(args, "--chat", c)
	}
	for _, k := range []string{"after", "before"} {
		if v := r.URL.Query().Get(k); v != "" {
			if !dateRe.MatchString(v) {
				return nil, false
			}
			if _, e := time.Parse("2006-01-02", v); e != nil {
				return nil, false
			}
			args = append(args, "--"+k, v)
		}
	}
	return args, true
}
func (s *server) query(w http.ResponseWriter, args ...string) {
	ctx, c := context.WithTimeout(context.Background(), 20*time.Second)
	defer c()
	out, e := s.cmd(ctx, true, args...).Output()
	if e != nil || !json.Valid(out) {
		http.Error(w, "query failed", 502)
		return
	}
	w.Write(out)
}
func (s *server) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "ok")
	})
	m.HandleFunc("/status", s.wrap("GET", false, func(w http.ResponseWriter, r *http.Request) {
		a, e := s.status()
		s.mu.Lock()
		defer s.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"authenticated": e == nil && a.Authenticated, "account_match": e == nil && s.match(a), "busy": s.busy != "", "state": s.state})
	}))
	m.HandleFunc("/chats", s.wrap("GET", true, func(w http.ResponseWriter, r *http.Request) {
		n, ok := intParam(r, "limit", 50, 200)
		if !ok {
			http.Error(w, "bad limit", 400)
			return
		}
		s.query(w, "--json", "chats", "list", "--limit", strconv.Itoa(n))
	}))
	m.HandleFunc("/messages", s.wrap("GET", true, func(w http.ResponseWriter, r *http.Request) {
		n, ok := intParam(r, "limit", 50, 200)
		args, ok2 := common(r, []string{"--json", "messages", "list", "--limit", strconv.Itoa(n)})
		if !ok || !ok2 {
			http.Error(w, "bad params", 400)
			return
		}
		s.query(w, args...)
	}))
	m.HandleFunc("/search", s.wrap("GET", true, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		n, ok := intParam(r, "limit", 50, 200)
		args, ok2 := common(r, []string{"--json", "messages", "search", "--limit", strconv.Itoa(n)})
		if !ok || !ok2 || len(q) == 0 || len(q) > 200 || strings.ContainsRune(q, 0) {
			http.Error(w, "bad params", 400)
			return
		}
		s.query(w, append(args, "--", q)...)
	}))
	m.HandleFunc("/sync", s.wrap("POST", true, func(w http.ResponseWriter, r *http.Request) {
		if !s.begin("sync") {
			http.Error(w, "busy", 409)
			return
		}
		ctx, c := context.WithTimeout(r.Context(), s.syncTimeout)
		defer c()
		err := s.cmd(ctx, false, "sync", "--once", "--presence-mode", "quiet", "--idle-exit", "10s", "--max-db-size", "200MB", "--max-messages", "10000").Run()
		state := "idle"
		if err != nil {
			state = "sync_failed"
		}
		s.end(state)
		if err != nil {
			http.Error(w, "sync failed", 502)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	m.HandleFunc("/auth/start", s.wrap("POST", false, func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.RawQuery) > 0 || s.days < 1 || s.days > 30 || s.maxChat < 1 || s.maxChat > 1000 {
			http.Error(w, "pairing scope not configured", 400)
			return
		}
		a, e := s.status()
		if e != nil {
			http.Error(w, "status unavailable", 503)
			return
		}
		if a.Authenticated {
			http.Error(w, "already paired; no changes made", 409)
			return
		}
		if !s.begin("pairing") {
			http.Error(w, "busy", 409)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.authTimeout)
		cmd := s.cmd(ctx, false, "--events", "auth", "--qr-format", "terminal", "--idle-exit", "10s", "--history-days", strconv.Itoa(s.days), "--history-max-per-chat", strconv.Itoa(s.maxChat))
		pipe, e := cmd.StderrPipe()
		if e != nil {
			s.end("auth_failed")
			cancel()
			http.Error(w, "start failed", 500)
			return
		}
		// stdout is discarded; stderr is parsed strictly as typed qr_code NDJSON only.
		if e = cmd.Start(); e != nil {
			s.end("auth_failed")
			cancel()
			http.Error(w, "start failed", 500)
			return
		}
		go func() {
			defer cancel()
			scan := bufio.NewScanner(pipe)
			scan.Buffer(make([]byte, 4096), 8192)
			for scan.Scan() {
				code := qrEvent(scan.Text())
				if code != "" {
					s.mu.Lock()
					s.qr = code
					s.mu.Unlock()
				}
			}
			_ = cmd.Wait()
			state := "auth_failed"
			{
				a, e := s.status()
				if e == nil && s.match(a) {
					state = "paired"
				} else if e == nil && a.Authenticated {
					state = "account_mismatch"
				}
			}
			s.end(state)
		}()
		json.NewEncoder(w).Encode(map[string]string{"state": "pairing"})
	}))
	m.HandleFunc("/auth/output", s.wrap("GET", false, func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		qr := ""
		if s.busy == "pairing" {
			qr = s.qr
		}
		json.NewEncoder(w).Encode(map[string]any{"state": s.state, "running": s.busy == "pairing", "qr": qr})
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health", "/status", "/chats", "/messages", "/search", "/sync", "/auth/start", "/auth/output":
			m.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
func main() {
	s := &server{token: os.Getenv("READER_TOKEN"), phone: os.Getenv("EXPECTED_PHONE"), store: envOr("WACLI_STORE_DIR", "/tmp/wacli-store"), bin: envOr("WACLI_BIN", "/usr/local/bin/wacli"), authTimeout: 180 * time.Second, syncTimeout: 90 * time.Second}
	if len(s.token) < 32 || !phoneRe.MatchString(s.phone) {
		panic("required authentication configuration missing")
	}
	s.days, _ = strconv.Atoi(os.Getenv("AUTH_HISTORY_DAYS"))
	s.maxChat, _ = strconv.Atoi(os.Getenv("AUTH_HISTORY_MAX_PER_CHAT"))
	if err := os.MkdirAll(s.store, 0700); err != nil {
		panic("store unavailable")
	}
	if err := os.Chmod(s.store, 0700); err != nil {
		panic("store protection failed")
	}
	srv := &http.Server{Addr: ":" + envOr("PORT", "10000"), Handler: s.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 100 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	panic(srv.ListenAndServe())
}
