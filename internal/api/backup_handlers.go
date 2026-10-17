package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/w0wzahh/blacknet/internal/backup"
)

// hBackup produces a zip download of configuration + database tables.
// ?include_history=true also exports the query log.
func (s *Server) hBackup(w http.ResponseWriter, r *http.Request) {
	include := r.URL.Query().Get("include_history") == "true"
	var buf bytes.Buffer
	if err := backup.Create(r.Context(), s.d.DB, &buf, include); err != nil {
		jerr(w, 500, "backup failed: "+err.Error())
		return
	}
	s.d.DB.Audit(r.Context(), "backup.create", fmt.Sprintf("history=%t", include))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="blacknet-backup-%s.zip"`, time.Now().UTC().Format("20060102-150405")))
	w.Write(buf.Bytes())
}

// hBackupInspect reads an uploaded archive and reports its contents without
// applying anything.
func (s *Server) hBackupInspect(w http.ResponseWriter, r *http.Request) {
	data, err := readBody(w, r, 256<<20)
	if err != nil {
		jerr(w, 400, "read body: "+err.Error())
		return
	}
	mf, counts, err := backup.Inspect(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	j(w, 200, map[string]any{"manifest": mf, "row_counts": counts})
}

// hRestore applies an uploaded archive. Requires ?confirm=true.
func (s *Server) hRestore(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("confirm") != "true" {
		jerr(w, 400, "pass confirm=true; restore replaces current configuration")
		return
	}
	data, err := readBody(w, r, 256<<20)
	if err != nil {
		jerr(w, 400, "read body: "+err.Error())
		return
	}
	if _, _, err := backup.Inspect(bytes.NewReader(data), int64(len(data))); err != nil {
		jerr(w, 400, err.Error())
		return
	}
	// Safety backup of the current DB file before replacing anything.
	var buf bytes.Buffer
	if err := backup.Create(r.Context(), s.d.DB, &buf, true); err == nil {
		path := s.d.Cfg.DBPath() + ".pre-restore-" + time.Now().UTC().Format("20060102-150405") + ".zip"
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			s.log.Warn("safety backup write failed", "err", err)
		}
	}
	if err := backup.Restore(r.Context(), s.d.DB, data); err != nil {
		jerr(w, 500, "restore failed: "+err.Error())
		return
	}
	_ = s.d.App.ReloadRules(r.Context())
	_ = s.d.App.ReloadUpstreams(r.Context())
	s.d.DB.Audit(r.Context(), "backup.restore", "")
	j(w, 200, map[string]any{"ok": true})
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	return io.ReadAll(r.Body)
}

// parseIP validates an IP string for client records.
func parseIP(s string) (netip.Addr, error) {
	return netip.ParseAddr(s)
}
