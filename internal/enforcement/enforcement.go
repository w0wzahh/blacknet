// Package enforcement manages verified network changes on external targets
// (routers). Every change goes through preview → backup → apply → verify and
// is recorded for rollback. Adapters report their real capabilities; nothing
// claims success it has not verified.
package enforcement

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/w0wzahh/blacknet/internal/database"
)

// Status values for recorded operations.
const (
	StPlanned    = "planned"
	StApplied    = "applied"
	StVerified   = "verified"
	StFailed     = "failed"
	StRolledBack = "rolled_back"
)

// Capability describes what an adapter can currently do.
type Capability struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
	// Reason explains unavailability honestly (missing creds, unsupported
	// router, host limitations).
	Reason    string `json:"reason,omitempty"`
	Verified  bool   `json:"verified"` // an end-to-end probe succeeded
	LastError string `json:"last_error,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

// Request asks an adapter for a change.
type Request struct {
	Integration string            `json:"integration"`
	Action      string            `json:"action"` // e.g. "redirect_dns"
	Params      map[string]string `json:"params"`
	// Credentials are supplied per request and never persisted.
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	HostKey  string `json:"host_key,omitempty"` // pinned SHA256 fingerprint
}

// Plan is a preview: human-readable commands/steps plus warnings.
type Plan struct {
	Integration string   `json:"integration"`
	Action      string   `json:"action"`
	Summary     string   `json:"summary"`
	Commands    []string `json:"commands"`
	Warnings    []string `json:"warnings"`
	// RequiresConfirm lists risky aspects that must be acknowledged.
	RequiresConfirm []string `json:"requires_confirm,omitempty"`
}

// Adapter performs verified changes on a target.
type Adapter interface {
	ID() string
	Name() string
	// Detect probes reachability/auth without changing anything.
	Detect(ctx context.Context, req Request) Capability
	// Preview renders the change without executing it.
	Preview(ctx context.Context, req Request) (*Plan, error)
	// Apply executes the plan and returns (result, backup, error).
	Apply(ctx context.Context, req Request) (result, backup string, err error)
	// Rollback restores the backup produced by Apply.
	Rollback(ctx context.Context, req Request, backup string) (string, error)
}

// Manager owns adapters and records operations in the DB.
type Manager struct {
	db       *database.DB
	adapters map[string]Adapter
}

// NewManager registers the built-in adapters.
func NewManager(db *database.DB) *Manager {
	m := &Manager{db: db, adapters: map[string]Adapter{}}
	for _, a := range []Adapter{&OpenWrt{}, &Manual{}} {
		m.adapters[a.ID()] = a
	}
	return m
}

// Integrations reports every adapter's capability for the supplied request
// (credentials in req are used for detection only).
func (m *Manager) Integrations(ctx context.Context, req Request) []Capability {
	out := make([]Capability, 0, len(m.adapters))
	for _, a := range m.adapters {
		out = append(out, a.Detect(ctx, req))
	}
	return out
}

// adapter resolves an id or errors honestly.
func (m *Manager) adapter(id string) (Adapter, error) {
	a, ok := m.adapters[id]
	if !ok {
		return nil, fmt.Errorf("unknown integration %q (available: %s)",
			id, strings.Join(m.ids(), ", "))
	}
	return a, nil
}

func (m *Manager) ids() []string {
	var out []string
	for id := range m.adapters {
		out = append(out, id)
	}
	return out
}

// Preview returns the rendered plan for a request and records it.
func (m *Manager) Preview(ctx context.Context, req Request) (*Plan, error) {
	a, err := m.adapter(req.Integration)
	if err != nil {
		return nil, err
	}
	plan, err := a.Preview(ctx, req)
	if err != nil {
		return nil, err
	}
	op := database.EnforcementOp{
		Integration: req.Integration, Action: req.Action,
		Status: StPlanned, Preview: strings.Join(plan.Commands, "\n"),
	}
	_ = m.db.RecordEnforcementOp(ctx, &op)
	return plan, nil
}

// Apply executes a change: the adapter performs backup + apply + verify; the
// operation and its backup are persisted regardless of outcome.
func (m *Manager) Apply(ctx context.Context, req Request) (*database.EnforcementOp, error) {
	a, err := m.adapter(req.Integration)
	if err != nil {
		return nil, err
	}
	plan, err := a.Preview(ctx, req)
	if err != nil {
		return nil, err
	}
	op := database.EnforcementOp{
		Integration: req.Integration, Action: req.Action,
		Status: StApplied, Preview: strings.Join(plan.Commands, "\n"),
	}
	result, backup, aerr := a.Apply(ctx, req)
	if aerr != nil {
		op.Status = StFailed
		op.Result = aerr.Error()
		_ = m.db.RecordEnforcementOp(ctx, &op)
		return nil, fmt.Errorf("apply failed (recorded as operation): %w", aerr)
	}
	op.Result = result
	_ = m.db.RecordEnforcementOp(ctx, &op)
	if backup != "" {
		_ = m.db.SaveEnforcementBackup(ctx, op.ID, backup)
	}
	return &op, nil
}

// Rollback restores a previous operation's backup on the same target.
func (m *Manager) Rollback(ctx context.Context, opID int64, req Request) error {
	a, err := m.adapter(req.Integration)
	if err != nil {
		return err
	}
	backup, err := m.db.EnforcementBackup(ctx, opID)
	if errors.Is(err, database.ErrNotFound) {
		return fmt.Errorf("operation %d has no stored backup", opID)
	}
	if err != nil {
		return err
	}
	result, rerr := a.Rollback(ctx, req, backup)
	status, res := StRolledBack, result
	if rerr != nil {
		status, res = StFailed, rerr.Error()
	}
	op := database.EnforcementOp{
		Integration: req.Integration, Action: "rollback",
		Status: status, Result: res,
	}
	_ = m.db.RecordEnforcementOp(ctx, &op)
	_ = m.db.UpdateEnforcementOpStatus(ctx, opID, status, "rollback: "+res)
	return rerr
}
