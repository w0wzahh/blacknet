// Package api implements the /api/v1 REST API, SSE live stream, static web
// hosting and the authentication/CSRF middleware.
package api

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
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

// Reloader is implemented by the application core; handlers call it to apply
// configuration changes without a restart.
type Reloader interface {
	ReloadRules(context.Context) error
	ReloadUpstreams(context.Context) error
	UpdateSettings(context.Context, map[string]json.RawMessage) (settings.Settings, map[string]string, error)
	GetSettings() settings.Settings
	GetDHCP(context.Context) (dhcp.Config, bool, []dhcp.Lease, error)
	SetDHCP(context.Context, dhcp.Config, bool) (map[string]string, error)
}

// Deps bundles everything the API needs.
type Deps struct {
	Cfg     *config.Config
	DB      *database.DB
	Engine  *filtering.Engine
	DNS     *dnsserver.Server
	Pool    *upstream.Pool
	Cache   *cache.Cache
	Lists   *blocklists.Manager
	Bus     *events.Bus[dnsserver.QueryEvent]
	QLog    *database.QueryLogger
	Auth    *auth.Manager
	App     Reloader
	Version string
	WebRoot string
}

// Server is the HTTP API + static file server.
type Server struct {
	d   Deps
	mux *http.ServeMux
	srv *http.Server
	log *slog.Logger
}

func New(d Deps) *Server {
	s := &Server{d: d, mux: http.NewServeMux(), log: slog.Default()}
	s.routes()
	return s
}

// Handler exposes the mux (useful for tests).
func (s *Server) Handler() http.Handler { return s.mux }

// Start serves HTTP on cfg.Web.Listen until ctx ends.
func (s *Server) Start(ctx context.Context, addr string) error {
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // SSE needs unbounded writes; per-handler limits apply
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("web listening", "addr", addr)
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutCtx)
	}
}

func (s *Server) routes() {
	pub := func(pat string, h http.HandlerFunc) {
		s.mux.HandleFunc(pat, h)
	}
	authd := func(pat string, h http.HandlerFunc) {
		s.mux.HandleFunc(pat, s.requireAuth(h))
	}

	pub("GET /api/v1/health", s.hHealth)
	pub("POST /api/v1/auth/login", s.hLogin)
	pub("GET /api/v1/auth/state", s.hAuthState)
	pub("POST /api/v1/setup/password", s.hSetupPassword)

	authd("POST /api/v1/auth/logout", s.hLogout)
	authd("GET /api/v1/status", s.hStatus)
	authd("GET /api/v1/about", s.hAbout)
	authd("GET /api/v1/audit", s.hAudit)

	authd("GET /api/v1/stats/summary", s.hStatsSummary)
	authd("GET /api/v1/stats/timeseries", s.hStatsTimeseries)
	authd("GET /api/v1/stats/top-domains", s.hTopDomains)
	authd("GET /api/v1/stats/top-clients", s.hTopClients)

	authd("GET /api/v1/queries", s.hQueries)
	authd("GET /api/v1/queries/export", s.hQueriesExport)
	authd("GET /api/v1/queries/live", s.hLive)

	authd("GET /api/v1/clients", s.hClients)
	authd("POST /api/v1/clients", s.hClientCreate)
	authd("PATCH /api/v1/clients/{id}", s.hClientPatch)
	authd("DELETE /api/v1/clients/{id}", s.hClientDelete)
	authd("POST /api/v1/clients/{id}/reset-stats", s.hClientReset)
	authd("GET /api/v1/clients/{id}/queries", s.hClientQueries)

	authd("GET /api/v1/blocklists", s.hBlocklists)
	authd("POST /api/v1/blocklists", s.hBlocklistCreate)
	authd("PATCH /api/v1/blocklists/{id}", s.hBlocklistPatch)
	authd("DELETE /api/v1/blocklists/{id}", s.hBlocklistDelete)
	authd("POST /api/v1/blocklists/{id}/refresh", s.hBlocklistRefresh)
	authd("POST /api/v1/blocklists/validate", s.hBlocklistValidate)

	authd("GET /api/v1/rules", s.hRules)
	authd("POST /api/v1/rules", s.hRuleCreate)
	authd("PATCH /api/v1/rules/{id}", s.hRulePatch)
	authd("DELETE /api/v1/rules/{id}", s.hRuleDelete)
	authd("POST /api/v1/rules/test", s.hRuleTest)
	authd("GET /api/v1/rules/export", s.hRulesExport)
	authd("POST /api/v1/rules/import", s.hRulesImport)

	authd("GET /api/v1/upstreams", s.hUpstreams)
	authd("POST /api/v1/upstreams", s.hUpstreamCreate)
	authd("PATCH /api/v1/upstreams/{id}", s.hUpstreamPatch)
	authd("DELETE /api/v1/upstreams/{id}", s.hUpstreamDelete)
	authd("POST /api/v1/upstreams/test", s.hUpstreamTest)

	authd("GET /api/v1/settings", s.hSettingsGet)
	authd("PATCH /api/v1/settings", s.hSettingsPatch)

	authd("POST /api/v1/cache/flush", s.hCacheFlush)
	authd("POST /api/v1/protection/enable", s.hProtection(true))
	authd("POST /api/v1/protection/disable", s.hProtection(false))
	authd("POST /api/v1/backup", s.hBackup)
	authd("POST /api/v1/restore", s.hRestore)
	authd("POST /api/v1/backup/inspect", s.hBackupInspect)

	authd("GET /api/v1/network/interfaces", s.hInterfaces)
	authd("GET /api/v1/network/info", s.hNetworkInfo)
	authd("GET /api/v1/network/port-check", s.hPortCheck)
	authd("GET /api/v1/diagnostics", s.hDiagnostics)

	authd("GET /api/v1/dhcp", s.hDHCPGet)
	authd("PUT /api/v1/dhcp", s.hDHCPSet)
	authd("POST /api/v1/dhcp/detect", s.hDHCPDetect)

	pub("GET /api/v1/openapi.yaml", s.hOpenAPI)

	// Static SPA (public; all sensitive operations require API auth).
	s.mux.Handle("GET /", s.spaHandler())
}

// ---------- middleware ----------

// requireAuth enforces session or bearer-token auth and CSRF protection for
// cookie-authenticated state-changing requests.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Setup mode: before an admin password exists, allow read-only GETs so
		// the first-run wizard can read status. Mutations still require auth.
		setupMode := !s.d.Auth.HasPassword()
		tok, ok := s.authenticated(r)
		_ = tok
		if !ok {
			if setupMode && r.Method == http.MethodGet {
				next(w, r)
				return
			}
			jerr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if isMutation(r.Method) && !bearerAuth(r) {
			// CSRF: cookie-authenticated mutations must carry the custom header
			// (impossible cross-origin without CORS) and any Origin header must
			// match the request host.
			if r.Header.Get("X-Requested-With") == "" {
				jerr(w, http.StatusForbidden, "missing CSRF header")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host {
					jerr(w, http.StatusForbidden, "origin mismatch")
					return
				}
			}
		}
		next(w, r)
	}
}

func isMutation(m string) bool {
	return m == http.MethodPost || m == http.MethodPatch || m == http.MethodPut || m == http.MethodDelete
}

func bearerAuth(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// authenticated reports whether the request carries a valid credential.
// Second return is true when authentication succeeded.
func (s *Server) authenticated(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return "", s.d.Auth.CheckAPIToken(strings.TrimPrefix(h, "Bearer "))
	}
	if c, err := r.Cookie("blacknet_session"); err == nil && c.Value != "" {
		return c.Value, s.d.Auth.ValidSession(c.Value)
	}
	return "", false
}

// ---------- helpers ----------

func j(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func jerr(w http.ResponseWriter, code int, msg string) {
	j(w, code, map[string]any{"error": msg})
}

func jerrFields(w http.ResponseWriter, code int, msg string, fields map[string]string) {
	j(w, code, map[string]any{"error": msg, "fields": fields})
}

const maxBody = 4 << 20

func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(out); err != nil {
		jerr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	var id int64
	s := r.PathValue("id")
	for _, c := range s {
		if c < '0' || c > '9' {
			jerr(w, http.StatusBadRequest, "invalid id")
			return 0, false
		}
		id = id*10 + int64(c-'0')
		if id > 1<<62 {
			jerr(w, http.StatusBadRequest, "invalid id")
			return 0, false
		}
	}
	if id == 0 {
		jerr(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
