package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*server, string, string) {
	t.Helper()
	d := t.TempDir()
	bin := filepath.Join(d, "wacli")
	status := filepath.Join(d, "status")
	calls := filepath.Join(d, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> '` + calls + `'
case "$*" in
 *'auth status'*) cat '` + status + `';;
 *' auth '*) printf 'PRIVATE_BOOTSTRAP_BODY\nhttps://wa.me/settings/linked_devices#testqr\n'; sleep 0.15; exit 1;;
 *) printf '{"success":true,"data":[]}';;
esac
`
	if e := os.WriteFile(bin, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	s := &server{token: strings.Repeat("X", 48), store: d, bin: bin, phone: "5493815412480", days: 1, maxChat: 100, authTimeout: time.Second, syncTimeout: time.Second}
	writeStatus(t, status, s.phone, true)
	return s, status, calls
}
func writeStatus(t *testing.T, p, phone string, yes bool) {
	t.Helper()
	b, _ := json.Marshal(envelope{Success: true, Data: account{Authenticated: yes, Phone: phone}})
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func request(s *server, method, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}
func TestAuthAndMethodGates(t *testing.T) {
	s, _, _ := fixture(t)
	for _, p := range []string{"/status", "/chats", "/messages", "/search?q=hi", "/auth/output", "/auth/start", "/sync"} {
		if w := request(s, "GET", p, ""); w.Code != 401 {
			t.Fatalf("%s %d", p, w.Code)
		}
	}
	for _, p := range []string{"/chats", "/messages", "/search?q=hi", "/status", "/auth/output"} {
		if w := request(s, "POST", p, s.token); w.Code != 405 {
			t.Fatalf("%s %d", p, w.Code)
		}
	}
	for _, p := range []string{"/send", "/auth/output/raw", "/messages/../../store"} {
		if w := request(s, "GET", p, s.token); w.Code != 404 {
			t.Fatalf("path %s %d", p, w.Code)
		}
	}
}
func TestAccountGates(t *testing.T) {
	s, p, calls := fixture(t)
	for _, phone := range []string{"11111111111", ""} {
		writeStatus(t, p, phone, true)
		for _, ep := range []string{"/messages", "/chats", "/search?q=hi"} {
			if w := request(s, "GET", ep, s.token); w.Code != 403 {
				t.Fatal(w.Code, w.Body.String())
			}
		}
		if w := request(s, "POST", "/sync", s.token); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	writeStatus(t, p, s.phone, false)
	if w := request(s, "GET", "/messages", s.token); w.Code != 403 {
		t.Fatal(w.Code)
	}
	os.WriteFile(p, []byte(`{"success":false,"data":{"authenticated":true,"phone":"5493815412480"}}`), 0600)
	if w := request(s, "GET", "/chats", s.token); w.Code != 403 {
		t.Fatal(w.Code)
	}
	os.WriteFile(p, []byte(`bad`), 0600)
	if w := request(s, "POST", "/sync", s.token); w.Code != 403 {
		t.Fatal(w.Code)
	}
	b, _ := os.ReadFile(calls)
	if strings.Contains(string(b), "sync --once") {
		t.Fatal("unauthorized sync")
	}
}
func TestQueries(t *testing.T) {
	s, _, calls := fixture(t)
	for _, p := range []string{"/chats?limit=0", "/messages?chat=--store", "/messages?chat=x%3Bid", "/messages?after=2026-99-99", "/messages?limit=201", "/search?q=", "/search?q=%00"} {
		w := request(s, "GET", p, s.token)
		if w.Code != 400 {
			t.Fatal(p, w.Code)
		}
	}
	for _, p := range []string{"/chats?limit=5", "/messages?chat=5493815412480@s.whatsapp.net", "/search?q=--store"} {
		w := request(s, "GET", p, s.token)
		if w.Code != 200 {
			t.Fatal(p, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cached")
		}
	}
	b, _ := os.ReadFile(calls)
	if !strings.Contains(string(b), "--read-only --json messages search --limit 50 -- --store") {
		t.Fatal("query not safely delimited", string(b))
	}
}
func TestPairingFailureNoLeakNoSync(t *testing.T) {
	s, p, calls := fixture(t)
	writeStatus(t, p, "", false)
	if w := request(s, "POST", "/auth/start?phone=123456789", s.token); w.Code != 400 {
		t.Fatal(w.Code)
	}
	s.days = 0
	if w := request(s, "POST", "/auth/start", s.token); w.Code != 400 {
		t.Fatal(w.Code)
	}
	s.days = 1
	if w := request(s, "POST", "/auth/start", s.token); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := request(s, "POST", "/auth/start", s.token)
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
	for i := 0; i < 20; i++ {
		w = request(s, "GET", "/auth/output", s.token)
		if strings.Contains(w.Body.String(), "PRIVATE") {
			t.Fatal("bootstrap leaked")
		}
		time.Sleep(15 * time.Millisecond)
	}
	w = request(s, "GET", "/auth/output", s.token)
	if strings.Contains(w.Body.String(), "testqr") || !strings.Contains(w.Body.String(), "auth_failed") {
		t.Fatal(w.Body.String())
	}
	b, _ := os.ReadFile(calls)
	if strings.Contains(string(b), "sync --") {
		t.Fatal("auto sync")
	}
}
func TestBoundedSync(t *testing.T) {
	s, _, calls := fixture(t)
	w := request(s, "POST", "/sync", s.token)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	b, _ := os.ReadFile(calls)
	str := string(b)
	if !strings.Contains(str, "--once --presence-mode quiet --idle-exit 10s") || strings.Contains(str, "--follow") {
		t.Fatal(str)
	}
}
func TestStatusRedaction(t *testing.T) {
	s, p, _ := fixture(t)
	writeStatus(t, p, "11111111111", true)
	w := request(s, "GET", "/status", s.token)
	if strings.Contains(w.Body.String(), "111111") || !strings.Contains(w.Body.String(), `"account_match":false`) {
		t.Fatal(w.Body.String())
	}
}

var _ http.Handler
