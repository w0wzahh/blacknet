// Package network provides LAN interface discovery and reachability checks
// for the setup wizard.
package network

import (
	"net"
	"net/netip"
	"time"
)

// Interface describes a usable local network interface.
type Interface struct {
	Name   string   `json:"name"`
	Addrs  []string `json:"addrs"` // CIDR form
	IPv4   []string `json:"ipv4"`  // plain addresses
	IsUp   bool     `json:"is_up"`
	IsLoop bool     `json:"is_loopback"`
}

// Interfaces lists up, non-loopback interfaces with their addresses.
func Interfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := []Interface{}
	for _, ifc := range ifaces {
		i := Interface{
			Name:   ifc.Name,
			IsUp:   ifc.Flags&net.FlagUp != 0,
			IsLoop: ifc.Flags&net.FlagLoopback != 0,
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			i.Addrs = append(i.Addrs, a.String())
			if ipnet, ok := a.(*net.IPNet); ok {
				if v4 := ipnet.IP.To4(); v4 != nil {
					i.IPv4 = append(i.IPv4, v4.String())
				}
			}
		}
		out = append(out, i)
	}
	return out, nil
}

// PrimaryIPv4 returns the first private IPv4 address found on an up,
// non-loopback interface — the best guess for the LAN address.
func PrimaryIPv4() (string, bool) {
	ifs, err := Interfaces()
	if err != nil {
		return "", false
	}
	for _, i := range ifs {
		if !i.IsUp || i.IsLoop {
			continue
		}
		for _, a := range i.IPv4 {
			if ip, err := netip.ParseAddr(a); err == nil && (ip.IsPrivate() || ip.IsLoopback()) {
				return a, true
			}
		}
	}
	return "", false
}

// CheckDNSPort tries binding UDP and TCP on addr to verify availability.
func CheckDNSPort(addr string) (udpOK, tcpOK bool, err error) {
	pc, err := net.ListenPacket("udp", addr)
	if err == nil {
		udpOK = true
		pc.Close()
	}
	l, err2 := net.Listen("tcp", addr)
	if err2 == nil {
		tcpOK = true
		l.Close()
	}
	if !udpOK || !tcpOK {
		if err != nil {
			return udpOK, tcpOK, err
		}
		return udpOK, tcpOK, err2
	}
	return true, true, nil
}

// GatewayGuess returns the default gateway guess: the /24 gateway (x.x.x.1)
// of the primary interface. Shown to the user as a hint only.
func GatewayGuess() string {
	ip, ok := PrimaryIPv4()
	if !ok {
		return ""
	}
	parts := splitDot(ip)
	if len(parts) != 4 {
		return ""
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".1"
}

func splitDot(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '.' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	return append(out, cur)
}

// ProbeTCP tries a TCP connect with a short timeout; used for diagnostics.
func ProbeTCP(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}
