// Package discovery builds the network inventory from passive observation:
// DNS client activity, DHCP leases (when Blacknet runs the DHCP server), and
// the host's neighbor table (ARP/NDP). It never claims certainty it cannot
// verify: every identity carries a provenance source, and MAC-derived
// identity is only as strong as the LAN's ARP hygiene.
package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Provenance labels for identity information.
const (
	SrcDNS      = "dns-observation" // saw queries from this address
	SrcDHCP     = "dhcp-lease"      // our DHCP server issued a lease
	SrcNeighbor = "neighbor-table"  // host ARP/NDP table
	SrcReverse  = "reverse-dns"     // PTR lookup — labeled, never trusted
	SrcManual   = "manual"
)

// Neighbor is one host-table entry.
type Neighbor struct {
	IP    netip.Addr `json:"ip"`
	MAC   string     `json:"mac"`
	Iface string     `json:"iface,omitempty"`
	State string     `json:"state,omitempty"`
}

// Neighbors reads the OS neighbor table. Returns nil (not an error) when
// unsupported or empty — callers surface "unavailable" honestly.
func Neighbors(ctx context.Context) []Neighbor {
	if ns := procNetARP(); len(ns) > 0 {
		return ns
	}
	return arpCommand(ctx)
}

// procNetARP parses Linux /proc/net/arp.
func procNetARP() []Neighbor {
	raw, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil
	}
	var out []Neighbor
	for i, line := range strings.Split(string(raw), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		// IP address | HW type | Flags | HW address | Mask | Device
		if len(f) < 6 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil || !isLAN(ip) {
			continue
		}
		mac := strings.ToUpper(f[3])
		if mac == "00:00:00:00:00:00" {
			continue
		}
		out = append(out, Neighbor{IP: ip, MAC: mac, Iface: f[5]})
	}
	return out
}

// arpCommand falls back to the `arp -a` table (Windows, BSD, busybox).
func arpCommand(ctx context.Context) []Neighbor {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(cctx, "arp", "-a").Output()
	if err != nil {
		return nil
	}
	var out []Neighbor
	for _, line := range strings.Split(string(raw), "\n") {
		// Windows: "  192.168.1.1          a4-b1-c1-...     dynamic"
		// Unix:    "? (192.168.1.1) at a4:b1:c1:... [ether] on eth0"
		f := strings.Fields(line)
		for i, tok := range f {
			tok = strings.Trim(tok, "()")
			ip, err := netip.ParseAddr(tok)
			if err != nil || !isLAN(ip) {
				continue
			}
			// MAC is usually the next-ish token containing : or -.
			for _, t := range f[i+1:] {
				if m := normalizeMAC(t); m != "" {
					out = append(out, Neighbor{IP: ip, MAC: m})
					break
				}
			}
			break
		}
	}
	return out
}

func normalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	if strings.Count(s, ":") == 5 {
		return strings.ToUpper(s)
	}
	if strings.Count(s, "-") == 5 {
		return strings.ToUpper(strings.ReplaceAll(s, "-", ":"))
	}
	return ""
}

// isLAN restricts to private/ULA addresses: public IPs in a neighbor table
// are unusual and not devices we manage.
func isLAN(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// Classifications.
const (
	ClsUnknown  = "unknown"
	ClsPhone    = "phone"
	ClsComputer = "computer"
	ClsTV       = "tv"
	ClsIoT      = "iot"
	ClsPrinter  = "printer"
	ClsRouter   = "router"
	ClsServer   = "server"
	ClsGame     = "game-console"
)

// Classify guesses a device type from its hostname using conservative
// keyword hints. Returns ClsUnknown when nothing matches — never guesses.
func Classify(hostname, mac string) string {
	h := strings.ToLower(hostname)
	switch {
	case strings.Contains(h, "iphone") || strings.Contains(h, "android") ||
		strings.Contains(h, "pixel") || strings.Contains(h, "galaxy"):
		return ClsPhone
	case strings.Contains(h, "ipad"):
		return ClsPhone
	case strings.Contains(h, "macbook") || strings.Contains(h, "imac") ||
		strings.Contains(h, "desktop") || strings.Contains(h, "laptop") ||
		strings.Contains(h, "thinkpad") || strings.Contains(h, "windows") ||
		strings.Contains(h, "pc"):
		return ClsComputer
	case strings.Contains(h, "tv") || strings.Contains(h, "roku") ||
		strings.Contains(h, "firetv") || strings.Contains(h, "chromecast") ||
		strings.Contains(h, "bravia") || strings.Contains(h, "appletv"):
		return ClsTV
	case strings.Contains(h, "printer") || strings.Contains(h, "epson") ||
		strings.Contains(h, "hp-") || strings.Contains(h, "brother"):
		return ClsPrinter
	case strings.Contains(h, "router") || strings.Contains(h, "gateway") ||
		strings.Contains(h, "openwrt"):
		return ClsRouter
	case strings.Contains(h, "playstation") || strings.Contains(h, "xbox") ||
		strings.Contains(h, "nintendo") || strings.Contains(h, "steamdeck"):
		return ClsGame
	case strings.Contains(h, "server") || strings.Contains(h, "nas") ||
		strings.Contains(h, "proxmox") || strings.Contains(h, "pve"):
		return ClsServer
	case strings.Contains(h, "esp") || strings.Contains(h, "tasmota") ||
		strings.Contains(h, "shelly") || strings.Contains(h, "hue") ||
		strings.Contains(h, "homekit"):
		return ClsIoT
	}
	return ClsUnknown
}

// HostnameHint extracts a usable name hint from a DHCP lease hostname.
// Empty is returned for junk values.
func HostnameHint(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if h == "" || h == "localhost" || len(h) > 63 {
		return ""
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return ""
	}
	return h
}

// Changes compares a client's stored fields with an observation and returns
// human-readable change descriptions (for discovery_events).
func Changes(ip netip.Addr, hostname, source string, haveAlias, haveHostname string) []string {
	var out []string
	if hint := HostnameHint(hostname); hint != "" && hint != strings.ToLower(haveHostname) {
		out = append(out, fmt.Sprintf("hostname for %s observed as %q via %s", ip, hint, source))
	}
	return out
}

// MACFromNeighbors returns the MAC for ip when present in the table.
func MACFromNeighbors(ns []Neighbor, ip netip.Addr) string {
	for _, n := range ns {
		if n.IP == ip {
			return n.MAC
		}
	}
	return ""
}

// Interfaces returns LAN interface addresses of this host — used to detect
// whether discovery is even possible (we must share an L2 with clients).
func Interfaces() []string {
	out := []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					out = append(out, ip4.String())
				}
			}
		}
	}
	return out
}
