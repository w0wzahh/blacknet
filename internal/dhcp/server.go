package dhcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Lease is one assigned address.
type Lease struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Config controls the DHCP server.
type Config struct {
	Enabled     bool   `json:"enabled"`
	InterfaceIP string `json:"interface_ip"` // the server's LAN address (also DNS answer)
	PoolStart   string `json:"pool_start"`
	PoolEnd     string `json:"pool_end"`
	Mask        string `json:"mask"`    // e.g. "255.255.255.0"
	Gateway     string `json:"gateway"` // usually the router
	LeaseSecs   uint32 `json:"lease_seconds"`
}

// Validate checks the config against sanity rules.
func (c *Config) Validate() error {
	server, err := netip.ParseAddr(c.InterfaceIP)
	if err != nil || !server.Is4() {
		return fmt.Errorf("interface_ip must be an IPv4 address")
	}
	start, err := netip.ParseAddr(c.PoolStart)
	if err != nil || !start.Is4() {
		return fmt.Errorf("pool_start must be an IPv4 address")
	}
	end, err := netip.ParseAddr(c.PoolEnd)
	if err != nil || !end.Is4() {
		return fmt.Errorf("pool_end must be an IPv4 address")
	}
	if !start.Less(end) && start != end {
		return fmt.Errorf("pool_start must be <= pool_end")
	}
	mask := net.ParseIP(c.Mask).To4()
	if mask == nil {
		return fmt.Errorf("mask must be a dotted IPv4 mask")
	}
	// Contiguous mask check.
	m := binary32(mask)
	inv := ^m
	if inv&(inv+1) != 0 {
		return fmt.Errorf("mask %s is not contiguous", c.Mask)
	}
	// Pool must be inside the interface's subnet.
	if !inNet(server, start, m) || !inNet(server, end, m) {
		return fmt.Errorf("pool %s-%s must be inside the interface subnet", start, end)
	}
	gw, err := netip.ParseAddr(c.Gateway)
	if err != nil || !gw.Is4() {
		return fmt.Errorf("gateway must be an IPv4 address")
	}
	if !inNet(server, gw, m) {
		return fmt.Errorf("gateway %s outside interface subnet", gw)
	}
	if start == server || end == server || start == gw || end == gw {
		return fmt.Errorf("pool must not include the server or gateway address")
	}
	if c.LeaseSecs < 60 || c.LeaseSecs > 86400*7 {
		return fmt.Errorf("lease_seconds must be between 60 and 604800")
	}
	return nil
}

func binary32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func inNet(server, addr netip.Addr, mask uint32) bool {
	s := binary32(net.ParseIP(server.String()).To4())
	a := binary32(net.ParseIP(addr.String()).To4())
	return s&mask == a&mask
}

// LeaseStore persists leases; implemented by the database layer.
type LeaseStore interface {
	LoadLeases(ctx context.Context) ([]Lease, error)
	SaveLease(ctx context.Context, l Lease) error
	DeleteLease(ctx context.Context, mac string) error
}

// Server is a minimal DHCPv4 server. Enabled explicitly; never started
// automatically.
type Server struct {
	cfg   Config
	store LeaseStore
	log   *slog.Logger

	mu     sync.Mutex
	leases map[string]Lease  // mac -> lease
	ipmap  map[string]string // ip -> mac

	conn   net.PacketConn
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a DHCP server for cfg; does not start it.
func New(cfg Config, store LeaseStore) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, store: store, log: slog.Default(),
		leases: map[string]Lease{}, ipmap: map[string]string{}}, nil
}

// Start binds UDP 67 on the configured interface and serves.
func (s *Server) Start(ctx context.Context) error {
	// Verify the configured IP really belongs to a local interface.
	ok, err := hasLocalIP(s.cfg.InterfaceIP)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s is not assigned to any local interface", s.cfg.InterfaceIP)
	}
	lc := net.ListenConfig{Control: broadcastControl}
	pc, err := lc.ListenPacket(ctx, "udp4", ":67")
	if err != nil {
		return fmt.Errorf("bind udp :67: %w", err)
	}
	if lns, err := s.store.LoadLeases(ctx); err == nil {
		for _, l := range lns {
			if l.ExpiresAt.After(time.Now()) {
				s.leases[l.MAC] = l
				s.ipmap[l.IP] = l.MAC
			}
		}
	}
	s.conn = pc
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.wg.Add(1)
	go s.serve(ctx)
	s.log.Warn("dhcp server started — ensure no other DHCP server is running on this LAN",
		"interface", s.cfg.InterfaceIP, "pool", s.cfg.PoolStart+"-"+s.cfg.PoolEnd)
	return nil
}

// Stop shuts the server down.
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	s.wg.Wait()
}

// Leases returns current leases.
func (s *Server) Leases() []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		if l.ExpiresAt.After(time.Now()) {
			out = append(out, l)
		}
	}
	return out
}

func (s *Server) serve(ctx context.Context) {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, src, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		p, err := Parse(buf[:n])
		if err != nil {
			continue
		}
		s.handle(src, p)
	}
}

func (s *Server) handle(src net.Addr, p *Packet) {
	if p.Op != opRequest || p.MsgType() == 0 {
		return
	}
	// Only serve clients that picked this server (or broadcast discovers).
	if sid := p.Options[optServerID]; len(sid) == 4 &&
		!net.IP(sid).Equal(net.ParseIP(s.cfg.InterfaceIP).To4()) &&
		p.MsgType() != msgDiscover {
		return
	}
	mac := p.MacString()
	s.mu.Lock()
	defer s.mu.Unlock()
	switch p.MsgType() {
	case msgDiscover:
		ip := s.offerIP(mac, p.RequestedIP())
		if ip == "" {
			return
		}
		s.send(p, msgOffer, net.ParseIP(ip).To4())
	case msgRequest:
		want := p.RequestedIP()
		if want == nil && p.CIAddr != nil && !p.CIAddr.IsUnspecified() {
			want = p.CIAddr
		}
		if cur, ok := s.leases[mac]; ok && want != nil && cur.IP == want.String() {
			s.commit(mac, cur.IP, p.Hostname())
			s.send(p, msgAck, net.ParseIP(cur.IP).To4())
			return
		}
		ip := s.offerIP(mac, want)
		if ip == "" || (want != nil && ip != want.String()) {
			s.send(p, msgNak, nil)
			return
		}
		s.commit(mac, ip, p.Hostname())
		s.send(p, msgAck, net.ParseIP(ip).To4())
	case msgRelease:
		if l, ok := s.leases[mac]; ok {
			delete(s.leases, mac)
			delete(s.ipmap, l.IP)
			_ = s.store.DeleteLease(context.Background(), mac)
		}
	case msgDecline:
		if l, ok := s.leases[mac]; ok {
			// Mark the IP unusable for a while by leasing it to a sentinel.
			s.leases["declined:"+l.IP] = Lease{MAC: "declined:" + l.IP, IP: l.IP,
				ExpiresAt: time.Now().Add(10 * time.Minute)}
		}
	}
}

// offerIP picks an address for mac: existing lease, else requested if free,
// else first free in pool. Must be called with s.mu held.
func (s *Server) offerIP(mac string, requested net.IP) string {
	if l, ok := s.leases[mac]; ok {
		return l.IP
	}
	if requested != nil && s.inPool(requested.String()) && s.ipmap[requested.String()] == "" {
		return requested.String()
	}
	cur := netip.MustParseAddr(s.cfg.PoolStart)
	end := netip.MustParseAddr(s.cfg.PoolEnd)
	for {
		if s.ipmap[cur.String()] == "" && s.leases["declined:"+cur.String()].MAC == "" {
			return cur.String()
		}
		if cur == end {
			return ""
		}
		cur = cur.Next()
	}
}

func (s *Server) inPool(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return !a.Less(netip.MustParseAddr(s.cfg.PoolStart)) &&
		!netip.MustParseAddr(s.cfg.PoolEnd).Less(a)
}

func (s *Server) commit(mac, ip, hostname string) {
	// Releasing any previous lease on the same IP for a different MAC.
	if old, ok := s.ipmap[ip]; ok && old != mac {
		delete(s.leases, old)
	}
	l := Lease{MAC: mac, IP: ip, Hostname: hostname,
		ExpiresAt: time.Now().Add(time.Duration(s.cfg.LeaseSecs) * time.Second)}
	s.leases[mac] = l
	s.ipmap[ip] = mac
	_ = s.store.SaveLease(context.Background(), l)
}

// send writes the reply to broadcast 255.255.255.255:68 (clients without an
// IP can't receive unicasts).
func (s *Server) send(p *Packet, msgType byte, yiaddr net.IP) {
	mask := net.ParseIP(s.cfg.Mask).To4()
	serverIP := net.ParseIP(s.cfg.InterfaceIP).To4()
	dnsIP := serverIP // Blacknet is the DNS server too
	out := p.Reply(msgType, yiaddr, serverIP, s.cfg.LeaseSecs,
		mask, net.ParseIP(s.cfg.Gateway).To4(), dnsIP)
	_, err := s.conn.WriteTo(out, &net.UDPAddr{IP: net.IPv4bcast, Port: 68})
	if err != nil {
		s.log.Debug("dhcp write failed", "err", err)
	}
}

// hasLocalIP reports whether s is assigned to any local interface.
func hasLocalIP(s string) (bool, error) {
	want, err := netip.ParseAddr(s)
	if err != nil {
		return false, err
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return false, err
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, err := netip.ParseAddr(ipn.IP.String()); err == nil && ip == want {
				return true, nil
			}
		}
	}
	return false, nil
}

// DetectOtherServers sends a DHCP DISCOVER on the broadcast address and waits
// briefly for OFFERs. Returns true if another server answered — caller should
// warn the user before enabling.
func DetectOtherServers(ctx context.Context, ifIP string) (bool, error) {
	lc := net.ListenConfig{Control: broadcastControl}
	pc, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		return false, err
	}
	defer pc.Close()
	pkt := &Packet{
		Op: opRequest, XID: 0x424c4b4e, Flags: bcastFlag,
		CHAddr: net.HardwareAddr{0x02, 0x42, 0x4e, 0x45, 0x54, 0x01},
	}
	raw := pkt.Reply(msgDiscover, net.IPv4zero, net.IPv4zero, 0, nil, nil, nil)
	// Rewrite op to request (Reply() sets opReply).
	raw[0] = opRequest
	if _, err := pc.WriteTo(raw, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		return false, fmt.Errorf("broadcast discover: %w", err)
	}
	deadline := time.Now().Add(2500 * time.Millisecond)
	pc.SetReadDeadline(deadline)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		resp, err := Parse(buf[:n])
		if err != nil {
			continue
		}
		if resp.XID == 0x424c4b4e && resp.MsgType() == msgOffer {
			return true, nil
		}
	}
	return false, nil
}
