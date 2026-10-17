package enforcement

import (
	"context"
	"fmt"
	"strings"
)

// Manual produces step-by-step instructions for routers Blacknet cannot
// automate. It never pretends to apply anything: Apply records the
// instructions and reports status "applied" only as "instructions issued",
// and Rollback explains what to revert.
type Manual struct{}

func (m *Manual) ID() string   { return "manual" }
func (m *Manual) Name() string { return "Manual router configuration" }

func (m *Manual) Detect(ctx context.Context, req Request) Capability {
	return Capability{
		ID: m.ID(), Name: m.Name(), Available: true, Verified: true,
		Notes: "Generates exact instructions for your router; nothing is changed automatically.",
	}
}

func (m *Manual) Preview(ctx context.Context, req Request) (*Plan, error) {
	ip := strings.TrimSpace(req.Params["blacknet_ip"])
	if ip == "" {
		return nil, fmt.Errorf("params.blacknet_ip required (this host's LAN address)")
	}
	switch req.Action {
	case "redirect_dns":
		return &Plan{
			Integration: m.ID(), Action: req.Action,
			Summary: fmt.Sprintf("Point your LAN at Blacknet (%s) for DNS", ip),
			Commands: []string{
				"In your router's admin UI, open the LAN/DHCP settings.",
				fmt.Sprintf("Set the DNS server handed to clients (DHCP option 6) to: %s", ip),
				"If the router supports it, add a NAT/firewall rule redirecting outbound TCP/UDP port 53 to " + ip + " — this catches devices with hardcoded DNS.",
				"Save and reboot the router if the DHCP option doesn't apply to existing leases.",
				"Verify on a client: nslookup example.com " + ip + " should answer; nslookup doubleclick.net " + ip + " should return NXDOMAIN.",
			},
			Warnings: []string{
				"Only LAN DNS is changed; encrypted DNS inside apps (DoH/DoT to 8.8.8.8 etc.) bypasses any DNS filter.",
				"If Blacknet stops, clients lose DNS — keep the host running or revert these settings.",
			},
		}, nil
	case "openwrt_cli":
		return &Plan{
			Integration: m.ID(), Action: req.Action,
			Summary: "OpenWrt commands to run manually over SSH",
			Commands: append([]string{
				"# SSH into the router, then:",
			}, mustCommands(req)...),
			Warnings: []string{"Run the commands verbatim; a backup of `uci export firewall` first is recommended."},
		}, nil
	}
	return nil, fmt.Errorf("unknown action %q (supported: redirect_dns, openwrt_cli)", req.Action)
}

func mustCommands(req Request) []string {
	cmds, err := redirectCommands(req)
	if err != nil {
		return []string{"# error: " + err.Error()}
	}
	return cmds
}

// Apply for Manual just returns the instruction text — no remote change.
func (m *Manual) Apply(ctx context.Context, req Request) (string, string, error) {
	plan, err := m.Preview(ctx, req)
	if err != nil {
		return "", "", err
	}
	return strings.Join(plan.Commands, "\n"), "", nil
}

// Rollback explains how to undo manual changes; there is nothing to restore.
func (m *Manual) Rollback(ctx context.Context, req Request, backup string) (string, error) {
	return "Manual changes cannot be rolled back automatically. Revert the DHCP DNS setting in your router UI to its previous value.", nil
}
