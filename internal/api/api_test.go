package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emre/blacknet/internal/auth"
	"github.com/emre/blacknet/internal/blocklists"
	"github.com/emre/blacknet/internal/cache"
	"github.com/emre/blacknet/internal/config"
	"github.com/emre/blacknet/internal/database"
	"github.com/emre/blacknet/internal/dhcp"
	"github.com/emre/blacknet/internal/dnsserver"
	"github.com/emre/blacknet/internal/events"
	"github.com/emre/blacknet/internal/filtering"
	"github.com/emre/blacknet/internal/settings"
	"github.com/emre/blacknet/internal/upstream"
)

type fakeReloader struct {
	settings.Settings
}

func (f *fakeReloader) ReloadRules(ctx context.Context) error     { return nil }
func (f *fakeReloader) ReloadUpstreams(ctx context.Context) error { return nil }
func (f *fakeReloader) GetSettings() settings.Settings            { return f.Settings }
func (f *fakeReloader) GetDHCP(ctx context.Context) (dhcp.Config, bool, []dhcp.Lease, error) {
	return dhcp.Config{}, false, nil, nil
}
func (f *fakeReloader) SetDHCP(ctx context.Context, c dhcp.Config, ack bool) (map[string]string, error) {
	return nil, nil
}
func (f *fakeReloader) UpdateSettings(ctx context.Context, patch map[string]json.RawMessage) (settings.Settings, map[string]string, error) {
	for k, v := range patch {
		switch k {
		case "protection_enabled":
			json.Unmarshal(v, &f.Settings.ProtectionEnabled)
		case "blocking_mode":
			json.Unmarshal(v, &f.Settings.BlockingMode)
		case "query_retention_days":
			json.Unmarshal(v, &f.Settings.QueryRetentionDays)
		}
	}
	if errs := settings.Validate(&f.Settings); len(errs) > 0 {
		return f.Settings, errs, nil
	}
	return f.Settings, nil, nil
}

func testServer(t *testing.T) (*Server, *database.DB) {
	t.Helper()
	return testServerAuth(t, true)
}

// testServerAuth builds a server; when withPassword is false no admin
// password exists (first-run setup mode).
func testServerAuth(t *testing.T, withPassword bool) (*Server, *database.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cfg := config.Default()
	cfg.DNS.Listen = []string{"127.0.0.1:0"}
	cfg.DataDir = dir
	pool, _ := upstream.NewPool(nil, false)
	am := auth.New("test-token")
	if withPassword {
		if err := am.SetPassword("test-password-123"); err != nil {
			t.Fatal(err)
		}
	}
	qlog := database.NewQueryLogger(db, 100)
	d := Deps{
		Cfg: cfg, DB: db, Engine: filtering.NewEngine(),
		DNS:     dnsserver.New(dnsserver.Options{Addrs: nil, Trusted: nil}),
		Pool:    pool,
		Cache:   cache.New(100, 0, time.Hour, time.Minute),
		Lists:   blocklists.NewManager(db, false, nil),
		Bus:     events.New[dnsserver.QueryEvent](),
		QLog:    qlog,
		Auth:    am,
		App:     &fakeReloader{Settings: settings.Default()},
		Version: "test",
	}
	return New(d), db
}

func req(t *testing.T, srv *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

func bearer() map[string]string {
	return map[string]string{"Authorization": "Bearer test-token"}
}

func TestUnauthenticatedRejected(t *testing.T) {
	srv, _ := testServer(t)
	for _, p := range []string{"/api/v1/status", "/api/v1/queries", "/api/v1/rules", "/api/v1/settings"} {
		w := req(t, srv, "GET", p, "", nil)
		if w.Code != 401 {
			t.Fatalf("%s: expected 401, got %d", p, w.Code)
		}
	}
	// health is public
	if w := req(t, srv, "GET", "/api/v1/health", "", nil); w.Code != 200 {
		t.Fatal("health must be public")
	}
}

func TestSetupModeAllowsReadOnly(t *testing.T) {
	srv, _ := testServerAuth(t, false)
	// GET works unauthenticated before a password exists (first-run wizard).
	if w := req(t, srv, "GET", "/api/v1/status", "", nil); w.Code != 200 {
		t.Fatalf("setup-mode GET status expected 200, got %d", w.Code)
	}
	// Mutations still require auth even in setup mode.
	if w := req(t, srv, "POST", "/api/v1/cache/flush", "", nil); w.Code != 401 {
		t.Fatalf("setup-mode POST expected 401, got %d", w.Code)
	}
}

func TestLoginFlowAndCSRF(t *testing.T) {
	srv, _ := testServerAuth(t, false)
	// set password (no auth needed, only works once)
	w := req(t, srv, "POST", "/api/v1/setup/password", `{"password":"hunter2-secret"}`, nil)
	if w.Code != 200 {
		t.Fatalf("setup password: %d %s", w.Code, w.Body.String())
	}
	// second call must fail
	w = req(t, srv, "POST", "/api/v1/setup/password", `{"password":"another-one"}`, nil)
	if w.Code != 409 {
		t.Fatalf("second setup must 409, got %d", w.Code)
	}
	// wrong password
	w = req(t, srv, "POST", "/api/v1/auth/login", `{"password":"wrong-password"}`, nil)
	if w.Code != 401 {
		t.Fatalf("bad login expected 401, got %d", w.Code)
	}
	// right password -> cookie
	w = req(t, srv, "POST", "/api/v1/auth/login", `{"password":"hunter2-secret"}`, nil)
	if w.Code != 200 {
		t.Fatalf("login: %d", w.Code)
	}
	cookie := w.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Fatal("expected session cookie")
	}
	cookieVal := strings.Split(strings.Split(cookie, ";")[0], "=")[1]
	// cookie-auth GET works
	w = req(t, srv, "GET", "/api/v1/status", "", map[string]string{"Cookie": "blacknet_session=" + cookieVal})
	if w.Code != 200 {
		t.Fatalf("cookie auth failed: %d", w.Code)
	}
	// cookie-auth POST without CSRF header -> 403
	w = req(t, srv, "POST", "/api/v1/cache/flush", "", map[string]string{"Cookie": "blacknet_session=" + cookieVal})
	if w.Code != 403 {
		t.Fatalf("expected CSRF 403, got %d", w.Code)
	}
	// with header -> 200
	w = req(t, srv, "POST", "/api/v1/cache/flush", "", map[string]string{
		"Cookie": "blacknet_session=" + cookieVal, "X-Requested-With": "XMLHttpRequest",
	})
	if w.Code != 200 {
		t.Fatalf("CSRF header should pass: %d", w.Code)
	}
	// bearer skips CSRF entirely
	w = req(t, srv, "POST", "/api/v1/cache/flush", "", bearer())
	if w.Code != 200 {
		t.Fatalf("bearer auth should skip CSRF: %d", w.Code)
	}
}

func TestRulesCRUDAndTest(t *testing.T) {
	srv, _ := testServer(t)
	w := req(t, srv, "POST", "/api/v1/rules", `{"domain":"ads.x","action":"block","scope":"tree"}`, bearer())
	if w.Code != 201 {
		t.Fatalf("create rule: %d %s", w.Code, w.Body.String())
	}
	var rule filtering.Rule
	json.Unmarshal(w.Body.Bytes(), &rule)
	// engine reflects new rule (fakeReloader reloads via real engine? no - check via rules/test)
	// fakeReloader doesn't push into engine; call reload manually:
	srv.d.Engine.Replace(mustRules(t, srv), nil, nil)
	w = req(t, srv, "POST", "/api/v1/rules/test", `{"domain":"sub.ads.x"}`, bearer())
	if w.Code != 200 {
		t.Fatal("rule test failed")
	}
	var dec filtering.Decision
	json.Unmarshal(w.Body.Bytes(), &dec)
	if !dec.Blocked {
		t.Fatal("tree rule should block subdomain")
	}
	// duplicate create -> 409
	w = req(t, srv, "POST", "/api/v1/rules", `{"domain":"ads.x","action":"block","scope":"tree"}`, bearer())
	if w.Code != 409 {
		t.Fatalf("expected 409 dup, got %d", w.Code)
	}
	// invalid domain -> 400
	w = req(t, srv, "POST", "/api/v1/rules", `{"domain":"not a domain!!","action":"block","scope":"exact"}`, bearer())
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	// patch disable
	w = req(t, srv, "PATCH", "/api/v1/rules/"+itoa(rule.ID), `{"enabled":false}`, bearer())
	if w.Code != 200 {
		t.Fatalf("patch: %d", w.Code)
	}
	// delete
	w = req(t, srv, "DELETE", "/api/v1/rules/"+itoa(rule.ID), "", bearer())
	if w.Code != 200 {
		t.Fatalf("delete: %d", w.Code)
	}
	w = req(t, srv, "DELETE", "/api/v1/rules/"+itoa(rule.ID), "", bearer())
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func mustRules(t *testing.T, srv *Server) []filtering.Rule {
	rules, err := srv.d.DB.ListRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func itoa(i int64) string {
	return strings.TrimSpace(jsonNumber(i))
}

func jsonNumber(i int64) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestSettingsPatch(t *testing.T) {
	srv, _ := testServer(t)
	w := req(t, srv, "PATCH", "/api/v1/settings", `{"blocking_mode":"null","query_retention_days":7}`, bearer())
	if w.Code != 200 {
		t.Fatalf("settings patch: %d %s", w.Code, w.Body.String())
	}
	w = req(t, srv, "PATCH", "/api/v1/settings", `{"blocking_mode":"bogus"}`, bearer())
	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid mode, got %d", w.Code)
	}
	// secret keys rejected
	w = req(t, srv, "PATCH", "/api/v1/settings", `{"admin_password":"x"}`, bearer())
	if w.Code != 400 {
		t.Fatal("password fields must be rejected here")
	}
}

func TestBlocklistValidation(t *testing.T) {
	srv, _ := testServer(t)
	// private/loopback rejected
	w := req(t, srv, "POST", "/api/v1/blocklists", `{"name":"x","url":"http://127.0.0.1/list.txt"}`, bearer())
	if w.Code != 400 {
		t.Fatalf("loopback http must be rejected, got %d", w.Code)
	}
	// http (non-tls) public rejected
	w = req(t, srv, "POST", "/api/v1/blocklists", `{"name":"x","url":"http://example.com/list.txt"}`, bearer())
	if w.Code != 400 {
		t.Fatalf("plain http must be rejected, got %d", w.Code)
	}
}

func TestQueriesEmptyState(t *testing.T) {
	srv, _ := testServer(t)
	w := req(t, srv, "GET", "/api/v1/queries", "", bearer())
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var out struct {
		Items []any `json:"items"`
		Total int64 `json:"total"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Total != 0 {
		t.Fatal("expected empty log")
	}
}

func TestProtectionConfirmRequired(t *testing.T) {
	srv, _ := testServer(t)
	w := req(t, srv, "POST", "/api/v1/protection/disable", "", bearer())
	if w.Code != 400 {
		t.Fatalf("disable without confirm must 400, got %d", w.Code)
	}
	w = req(t, srv, "POST", "/api/v1/protection/disable?confirm=true", "", bearer())
	if w.Code != 200 {
		t.Fatalf("disable with confirm: %d", w.Code)
	}
}
