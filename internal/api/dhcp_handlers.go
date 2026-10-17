package api

import (
	"net/http"

	"github.com/emre/blacknet/internal/dhcp"
)

// hDHCPGet returns config, running state and active leases.
func (s *Server) hDHCPGet(w http.ResponseWriter, r *http.Request) {
	cfg, running, leases, err := s.d.App.GetDHCP(r.Context())
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, map[string]any{
		"config":  cfg,
		"running": running,
		"leases":  leases,
	})
}

// hDHCPSet validates + applies config. Body: {config:{...}, acknowledge_conflict}
func (s *Server) hDHCPSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config              dhcp.Config `json:"config"`
		AcknowledgeConflict bool        `json:"acknowledge_conflict"`
	}
	if !decode(w, r, &body) {
		return
	}
	problems, err := s.d.App.SetDHCP(r.Context(), body.Config, body.AcknowledgeConflict)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	if len(problems) > 0 {
		jerrFields(w, 400, "DHCP configuration rejected", problems)
		return
	}
	j(w, 200, map[string]any{"ok": true})
}

// hDHCPDetect probes the LAN for an existing DHCP server (DISCOVER + wait for
// OFFER) so the UI can warn before enabling ours.
func (s *Server) hDHCPDetect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		InterfaceIP string `json:"interface_ip"`
	}
	if !decode(w, r, &body) {
		return
	}
	found, err := dhcp.DetectOtherServers(r.Context(), body.InterfaceIP)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	j(w, 200, map[string]any{"other_dhcp_server_detected": found})
}
