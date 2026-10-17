package enforcement

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// OpenWrt manages DNS redirection on an OpenWrt router over SSH.
// Credentials arrive per request and are never persisted by Blacknet.
// The host key must be pinned (TOFU): the first Detect surfaces the
// fingerprint, and Apply/Rollback refuse to run without it.
type OpenWrt struct{}

func (o *OpenWrt) ID() string   { return "openwrt" }
func (o *OpenWrt) Name() string { return "OpenWrt router (SSH)" }

// sshCmd is the connector used in tests to substitute an in-process server.
var sshDial = func(ctx context.Context, req Request) (*ssh.Client, string, error) {
	if req.Host == "" {
		return nil, "", fmt.Errorf("host required")
	}
	port := req.Port
	if port == 0 {
		port = 22
	}
	var pinnedFP string
	cfg := &ssh.ClientConfig{
		User:            req.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(req.Password)},
		Timeout:         10 * time.Second,
		HostKeyCallback: hostKeyChecker(req.HostKey, &pinnedFP),
	}
	if req.Username == "" || req.Password == "" {
		return nil, "", fmt.Errorf("username and password required (not persisted)")
	}
	addr := net.JoinHostPort(req.Host, fmt.Sprint(port))
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("connect %s: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		// Host-key errors carry the observed fingerprint for TOFU pinning.
		if pinnedFP != "" && strings.Contains(err.Error(), "host key") {
			return nil, "", fmt.Errorf("host key not pinned; observed fingerprint %s — verify it belongs to your router, then resubmit with host_key=%s", pinnedFP, pinnedFP)
		}
		return nil, "", err
	}
	return ssh.NewClient(c, chans, reqs), pinnedFP, nil
}

// hostKeyChecker pins by SHA256 fingerprint when expected is non-empty and
// always records the observed fingerprint for the caller.
func hostKeyChecker(expected string, observed *string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		sum := sha256.Sum256(key.Marshal())
		fp := "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
		*observed = fp
		if expected == "" {
			return fmt.Errorf("host key not pinned")
		}
		if expected != fp {
			return fmt.Errorf("host key mismatch: expected %s, got %s", expected, fp)
		}
		return nil
	}
}

// run executes one remote command and returns combined output.
func run(ctx context.Context, c *ssh.Client, cmd string) (string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		return out.String(), ctx.Err()
	case err := <-done:
		return out.String(), err
	}
}

// Detect probes SSH connectivity and identifies the firewall backend.
func (o *OpenWrt) Detect(ctx context.Context, req Request) Capability {
	cap := Capability{ID: o.ID(), Name: o.Name()}
	c, fp, err := sshDial(ctx, req)
	if err != nil {
		cap.Reason = err.Error()
		if fp != "" {
			cap.Notes = "observed host key " + fp
		}
		return cap
	}
	defer c.Close()
	cap.Available = true
	fw, _ := run(ctx, c, `sh -c 'command -v fw4 >/dev/null && echo fw4 || (command -v fw3 >/dev/null && echo fw3 || echo unknown)'`)
	cap.Notes = "firewall backend: " + strings.TrimSpace(fw)
	ver, _ := run(ctx, c, `sh -c 'cat /etc/openwrt_release 2>/dev/null | head -3'`)
	if v := strings.TrimSpace(ver); v != "" {
		cap.Notes += "; " + strings.ReplaceAll(v, "\n", "; ")
	}
	// Verification: a real round-trip succeeded.
	cap.Verified = true
	return cap
}

// redirectCommands renders the uci commands that hijack LAN DNS to Blacknet.
// src_ip "!ip" exclusion keeps Blacknet's own upstream queries un-looped
// (negation is supported by both fw3/iptables and fw4/nftables uci parsing).
func redirectCommands(req Request) ([]string, error) {
	bnIP := strings.TrimSpace(req.Params["blacknet_ip"])
	ip, err := netip.ParseAddr(bnIP)
	if err != nil {
		return nil, fmt.Errorf("params.blacknet_ip must be this host's LAN IPv4/IPv6, got %q", bnIP)
	}
	srcZone := req.Params["src_zone"]
	if srcZone == "" {
		srcZone = "lan"
	}
	cmds := []string{
		"uci add firewall redirect",
		"uci set firewall.@redirect[-1].name='blacknet_dns'",
		"uci set firewall.@redirect[-1].src='" + srcZone + "'",
		"uci set firewall.@redirect[-1].proto='tcp udp'",
		"uci set firewall.@redirect[-1].src_dport='53'",
		"uci set firewall.@redirect[-1].src_ip='!" + ip.String() + "'",
		"uci set firewall.@redirect[-1].dest_ip='" + ip.String() + "'",
		"uci set firewall.@redirect[-1].dest_port='53'",
		"uci set firewall.@redirect[-1].target='DNAT'",
		"uci commit firewall",
		"/etc/init.d/firewall reload",
	}
	return cmds, nil
}

// Preview renders the pending change.
func (o *OpenWrt) Preview(ctx context.Context, req Request) (*Plan, error) {
	switch req.Action {
	case "redirect_dns":
		cmds, err := redirectCommands(req)
		if err != nil {
			return nil, err
		}
		return &Plan{
			Integration: o.ID(), Action: req.Action,
			Summary:  fmt.Sprintf("Redirect all LAN DNS (port 53) to Blacknet at %s, excluding Blacknet itself", req.Params["blacknet_ip"]),
			Commands: cmds,
			Warnings: []string{
				"All LAN clients' DNS will be forwarded to Blacknet; if Blacknet stops, DNS breaks network-wide.",
				"Devices using hardcoded DNS (8.8.8.8, DoH inside apps) are redirected too — encrypted DNS inside apps cannot be intercepted.",
			},
			RequiresConfirm: []string{"A backup of the firewall config is stored first; rollback restores it."},
		}, nil
	case "remove_redirect":
		return &Plan{
			Integration: o.ID(), Action: req.Action,
			Summary:  "Remove all Blacknet DNS redirect rules",
			Commands: removeCommands(),
			Warnings: []string{"LAN clients will again use the router's DNS directly."},
		}, nil
	}
	return nil, fmt.Errorf("unknown action %q (supported: redirect_dns, remove_redirect)", req.Action)
}

func removeCommands() []string {
	return []string{
		// uci show emits anonymous sections as cfgXXXX; delete each whose
		// name starts with blacknet_.
		`for s in $(uci show firewall | sed -n "s/^firewall\.\([a-z0-9]*\)\.name='blacknet_.*'/\1/p"); do uci delete firewall.$s; done`,
		"uci commit firewall",
		"/etc/init.d/firewall reload",
	}
}

// Apply backs up the firewall package, applies the change, and verifies the
// redirect exists afterwards.
func (o *OpenWrt) Apply(ctx context.Context, req Request) (string, string, error) {
	c, _, err := sshDial(ctx, req)
	if err != nil {
		return "", "", err
	}
	defer c.Close()

	backup, err := run(ctx, c, "uci export firewall")
	if err != nil {
		return "", "", fmt.Errorf("backup: %w", err)
	}
	var cmds []string
	switch req.Action {
	case "redirect_dns":
		cmds, err = redirectCommands(req)
	case "remove_redirect":
		cmds = removeCommands()
	default:
		return "", "", fmt.Errorf("unknown action %q", req.Action)
	}
	if err != nil {
		return "", "", err
	}
	var log strings.Builder
	for _, cmd := range cmds {
		out, err := run(ctx, c, "sh -c "+shellQuote(cmd))
		fmt.Fprintf(&log, "$ %s\n%s\n", cmd, out)
		if err != nil {
			return log.String(), backup, fmt.Errorf("command failed: %s → %s", cmd, strings.TrimSpace(out))
		}
	}
	// Verify the redirect landed.
	verify, err := run(ctx, c, "uci show firewall | grep -c blacknet_dns")
	if err != nil {
		return log.String(), backup, fmt.Errorf("verification failed: %w", err)
	}
	if req.Action == "redirect_dns" && strings.TrimSpace(verify) == "0" {
		return log.String(), backup, fmt.Errorf("verification failed: redirect section not present after commit")
	}
	return log.String(), backup, nil
}

// Rollback restores the saved `uci export firewall` output.
func (o *OpenWrt) Rollback(ctx context.Context, req Request, backup string) (string, error) {
	c, _, err := sshDial(ctx, req)
	if err != nil {
		return "", err
	}
	defer c.Close()
	var log strings.Builder
	for _, cmd := range []string{
		"uci import firewall <<'EOF'\n" + backup + "\nEOF",
		"/etc/init.d/firewall reload",
	} {
		out, err := run(ctx, c, "sh -c "+shellQuote(cmd))
		fmt.Fprintf(&log, "$ %s\n%s\n", cmd, out)
		if err != nil {
			return log.String(), fmt.Errorf("rollback command failed: %s", cmd)
		}
	}
	return log.String(), nil
}

// shellQuote wraps s for `sh -c`.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
