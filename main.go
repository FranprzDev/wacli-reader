package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
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

var (
	token     = os.Getenv("READER_TOKEN")
	store     = envOr("WACLI_STORE_DIR", "/tmp/wacli-store")
	bin       = envOr("WACLI_BIN", "/usr/local/bin/wacli")
	chatRe    = regexp.MustCompile(`^[A-Za-z0-9@._+ \-]{1,64}$`)
	dateRe    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	phoneRe   = regexp.MustCompile(`^\d{8,15}$`)
	mu        sync.Mutex
	authLog   []string
	authBusy  bool
	syncing   bool
	failMu    sync.Mutex
	fails     int
	failSince time.Time
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func wacli(ctx context.Context, readOnly bool, args ...string) *exec.Cmd {
	full := []string{"--store", store}
	if readOnly {
		full = append(full, "--read-only")
	}
	full = append(full, args...)
	c := exec.CommandContext(ctx, bin, full...)
	c.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp"}
	return c
}

func authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		failMu.Lock()
		if time.Since(failSince) > time.Minute {
			fails = 0
		}
		blocked := fails >= 10
		failMu.Unlock()
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if blocked || token == "" || len(got) != len(token) || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			failMu.Lock()
			fails++
			failSince = time.Now()
			failMu.Unlock()
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func intParam(r *http.Request, k string, def, max int) (int, bool) {
	v := r.URL.Query().Get(k)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > max {
		return 0, false
	}
	return n, true
}

func run(w http.ResponseWriter, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := wacli(ctx, true, args...).Output()
	if err != nil {
		http.Error(w, "query failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func common(r *http.Request, args []string) ([]string, bool) {
	q := r.URL.Query()
	if c := q.Get("chat"); c != "" {
		if !chatRe.MatchString(c) {
			return nil, false
		}
		args = append(args, "--chat", c)
	}
	for _, k := range []string{"after", "before"} {
		if v := q.Get(k); v != "" {
			if !dateRe.MatchString(v) {
				return nil, false
			}
			args = append(args, "--"+k, v)
		}
	}
	return args, true
}

func startSync() {
	mu.Lock()
	if syncing {
		mu.Unlock()
		return
	}
	syncing = true
	mu.Unlock()
	go func() {
		for {
			// sync is the only writer: local DB only, no sends, quiet presence
			c := wacli(context.Background(), false, "sync", "--follow", "--presence-mode", "quiet", "--max-db-size", "200MB")
			_ = c.Run()
			time.Sleep(30 * time.Second)
		}
	}()
}

func main() {
	if err := os.MkdirAll(store, 0o700); err != nil {
		panic(err)
	}
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })

	http.HandleFunc("/status", authed(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, _ := wacli(ctx, true, "--json", "auth", "status").CombinedOutput()
		mu.Lock()
		s := syncing
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"auth": strings.TrimSpace(string(out)), "sync_running": s})
	}))

	http.HandleFunc("/chats", authed(func(w http.ResponseWriter, r *http.Request) {
		n, ok := intParam(r, "limit", 50, 200)
		if !ok {
			http.Error(w, "bad limit", 400)
			return
		}
		run(w, "--json", "chats", "list", "--limit", strconv.Itoa(n))
	}))

	http.HandleFunc("/messages", authed(func(w http.ResponseWriter, r *http.Request) {
		n, ok := intParam(r, "limit", 50, 200)
		args, ok2 := common(r, []string{"--json", "messages", "list", "--limit", strconv.Itoa(n)})
		if !ok || !ok2 {
			http.Error(w, "bad params", 400)
			return
		}
		run(w, args...)
	}))

	http.HandleFunc("/search", authed(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		n, ok := intParam(r, "limit", 50, 200)
		args, ok2 := common(r, []string{"--json", "messages", "search", "--limit", strconv.Itoa(n)})
		if !ok || !ok2 || q == "" || len(q) > 200 || strings.ContainsAny(q, "\x00") {
			http.Error(w, "bad params", 400)
			return
		}
		run(w, append(args, "--", q)...)
	}))

	// pairing: POST /auth/start[?phone=<digits>] then GET /auth/output; QR/code only for the owner
	http.HandleFunc("/auth/start", authed(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST", 405)
			return
		}
		args := []string{"auth", "--qr-format", "text", "--idle-exit", "90s", "--history-days", "30"}
		if p := r.URL.Query().Get("phone"); p != "" {
			if !phoneRe.MatchString(p) {
				http.Error(w, "bad phone", 400)
				return
			}
			args = append(args, "--phone", p)
		}
		mu.Lock()
		if authBusy {
			mu.Unlock()
			http.Error(w, "auth already running", 409)
			return
		}
		authBusy = true
		authLog = nil
		mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		c := wacli(ctx, false, args...)
		stdout, _ := c.StdoutPipe()
		c.Stderr = c.Stdout
		if err := c.Start(); err != nil {
			cancel()
			mu.Lock()
			authBusy = false
			mu.Unlock()
			http.Error(w, "start failed", 500)
			return
		}
		go func() {
			sc := bufio.NewScanner(stdout)
			sc.Buffer(make([]byte, 64*1024), 256*1024)
			for sc.Scan() {
				mu.Lock()
				authLog = append(authLog, sc.Text())
				if len(authLog) > 40 {
					authLog = authLog[len(authLog)-40:]
				}
				mu.Unlock()
			}
			_ = c.Wait()
			cancel()
			mu.Lock()
			authBusy = false
			mu.Unlock()
			startSync()
		}()
		fmt.Fprint(w, "started")
	}))

	http.HandleFunc("/auth/output", authed(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"running": authBusy, "lines": authLog})
	}))

	// resume sync after restart if already paired
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, _ := wacli(ctx, true, "--json", "auth", "status").CombinedOutput()
		if strings.Contains(string(out), `\"authenticated\":true`) || strings.Contains(string(out), `"authenticated":true`) {
			startSync()
		}
	}()

	port := envOr("PORT", "10000")
	srv := &http.Server{Addr: ":" + port, ReadHeaderTimeout: 5 * time.Second}
	panic(srv.ListenAndServe())
}
