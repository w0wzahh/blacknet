// Package dnsserver implements Blacknet's DNS server: UDP/TCP listeners,
// trusted-client enforcement, filtering, caching and upstream forwarding.
package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/w0wzahh/blacknet/internal/cache"
	"github.com/w0wzahh/blacknet/internal/filtering"
)

// Blocking mode values.
const (
	ModeNXDomain = "nxdomain"
	ModeNullIP   = "null"
)

// QueryEvent describes a single DNS query for logging/statistics/SSE.
type QueryEvent struct {
	Time       time.Time `json:"time"`
	ClientIP   string    `json:"client_ip"`
	ClientID   int64     `json:"client_id"`
	GroupID    int64     `json:"group_id"`
	Domain     string    `json:"domain"`
	QType      uint16    `json:"qtype"`
	QTypeName  string    `json:"qtype_name"`
	Blocked    bool      `json:"blocked"`
	Reason     string    `json:"reason"`
	RCode      int       `json:"rcode"`
	RCodeName  string    `json:"rcode_name"`
	LatencyMs  float64   `json:"latency_ms"`
	UpstreamMs float64   `json:"upstream_ms"`
	Cached     bool      `json:"cached"`
	// DNSSEC is the upstream-validation outcome for forwarded queries:
	// "", "authenticated" (AD set) or "unsigned" (DO requested, AD clear).
	DNSSEC string `json:"dnssec,omitempty"`
}

// Resolver is anything that can forward a DNS query (the upstream pool).
type Resolver interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(ctx context.Context, req *dns.Msg) (*dns.Msg, error)

// Exchange calls f.
func (f ResolverFunc) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return f(ctx, req)
}

// LocalStore serves local DNS records. Implemented by internal/localdns.
type LocalStore interface {
	// Answer returns a complete response for q, or nil when no local record
	// applies (the query continues through the normal pipeline).
	Answer(q dns.Question) *dns.Msg
}

// Options configures a Server.
type Options struct {
	Addrs    []string       // "ip:port" listen addresses
	Trusted  []netip.Prefix // allowed client CIDRs
	Engine   *filtering.Engine
	Upstream Resolver
	Cache    *cache.Cache
	Publish  func(QueryEvent) // async event sink (must not block)
	// SubjectFor resolves a source IP into its client id and policy group.
	SubjectFor func(netip.Addr) filtering.Subject
	// Local answers local DNS records before filtering (may be nil).
	Local LocalStore
	// ResolverFor returns the upstream for a policy group (nil = default).
	ResolverFor func(groupID int64) Resolver
	// DNSSECUpstream passes the DO bit to upstreams and records the AD flag
	// in the response (upstream-side validation; Blacknet does not itself
	// validate signatures).
	DNSSECUpstream bool
	Logger         *slog.Logger
}

// Server is a concurrent UDP+TCP DNS server.
type Server struct {
	opts Options

	blockMode atomic.Int32 // 0=nxdomain, 1=null
	dnssec    atomic.Bool  // DO passthrough, runtime-toggleable

	mu    sync.Mutex
	svrs  []*dns.Server
	conns []net.PacketConn
	lsns  []net.Listener

	queries  atomic.Int64
	blocked  atomic.Int64
	refused  atomic.Int64
	failures atomic.Int64

	log *slog.Logger
}

func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Server{opts: opts, log: opts.Logger}
	s.dnssec.Store(opts.DNSSECUpstream)
	return s
}

// SetDNSSECUpstream toggles DO-bit passthrough and AD recording at runtime.
func (s *Server) SetDNSSECUpstream(on bool) { s.dnssec.Store(on) }

// SetBlockingMode switches between ModeNXDomain and ModeNullIP at runtime.
func (s *Server) SetBlockingMode(mode string) error {
	switch mode {
	case ModeNXDomain:
		s.blockMode.Store(0)
	case ModeNullIP:
		s.blockMode.Store(1)
	default:
		return fmt.Errorf("unknown blocking mode %q", mode)
	}
	return nil
}

// BlockingMode returns the current mode name.
func (s *Server) BlockingMode() string {
	if s.blockMode.Load() == 1 {
		return ModeNullIP
	}
	return ModeNXDomain
}

// Counters for the status API.
func (s *Server) Counters() (queries, blocked, refused, failures int64) {
	return s.queries.Load(), s.blocked.Load(), s.refused.Load(), s.failures.Load()
}

// Start binds every configured address for both UDP and TCP and serves in the
// background. A bind failure on any address aborts startup and closes what
// was already opened.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, addr := range s.opts.Addrs {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			s.closeLocked()
			return fmt.Errorf("bind udp %s: %w", addr, err)
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			pc.Close()
			s.closeLocked()
			return fmt.Errorf("bind tcp %s: %w", addr, err)
		}
		udpSrv := &dns.Server{PacketConn: pc, Handler: s, UDPSize: dns.DefaultMsgSize}
		tcpSrv := &dns.Server{Listener: l, Handler: s}
		s.conns = append(s.conns, pc)
		s.lsns = append(s.lsns, l)
		s.svrs = append(s.svrs, udpSrv, tcpSrv)
		go func() {
			if err := udpSrv.ActivateAndServe(); err != nil {
				s.log.Error("udp listener stopped", "addr", addr, "err", err)
			}
		}()
		go func() {
			if err := tcpSrv.ActivateAndServe(); err != nil {
				s.log.Error("tcp listener stopped", "addr", addr, "err", err)
			}
		}()
		s.log.Info("dns listening", "addr", addr)
	}
	return nil
}

// Shutdown stops all listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	for _, srv := range s.svrs {
		if err := srv.ShutdownContext(ctx); err != nil && first == nil {
			first = err
		}
	}
	s.closeLocked()
	return first
}

func (s *Server) closeLocked() {
	for _, c := range s.conns {
		c.Close()
	}
	for _, l := range s.lsns {
		l.Close()
	}
	s.conns, s.lsns, s.svrs = nil, nil, nil
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	s.queries.Add(1)

	clientIP, ok := remoteIP(w.RemoteAddr())
	ev := QueryEvent{Time: start.UTC(), ClientIP: clientIP.String()}
	defer func() {
		ev.LatencyMs = float64(time.Since(start)) / float64(time.Millisecond)
		if s.opts.Publish != nil {
			s.opts.Publish(ev)
		}
	}()

	if !ok || !s.trusted(clientIP) {
		s.refused.Add(1)
		ev.Reason = string(filtering.ReasonUntrustedClient)
		m := new(dns.Msg).SetRcode(r, dns.RcodeRefused)
		ev.RCode, ev.RCodeName = m.Rcode, dns.RcodeToString[m.Rcode]
		_ = w.WriteMsg(m)
		return
	}

	var sub filtering.Subject
	if s.opts.SubjectFor != nil {
		sub = s.opts.SubjectFor(clientIP)
		sub.Now = ev.Time
	}
	ev.ClientID, ev.GroupID = sub.ClientID, sub.GroupID

	if len(r.Question) == 0 {
		ev.Reason = "malformed query"
		m := new(dns.Msg).SetRcode(r, dns.RcodeFormatError)
		ev.RCode, ev.RCodeName = m.Rcode, dns.RcodeToString[m.Rcode]
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	domain := filtering.Normalize(q.Name)
	ev.Domain = domain
	ev.QType = q.Qtype
	ev.QTypeName = dns.TypeToString[q.Qtype]

	// Local DNS records answer before filtering and upstream forwarding
	// (authoritative for local names; documented precedence level 0).
	if s.opts.Local != nil {
		if m := s.opts.Local.Answer(q); m != nil {
			m.Id = r.Id
			ev.Reason = "local record"
			ev.RCode, ev.RCodeName = m.Rcode, dns.RcodeToString[m.Rcode]
			_ = w.WriteMsg(m)
			return
		}
	}

	// Filtering decision.
	var dec filtering.Decision
	if s.opts.Engine != nil {
		dec = s.opts.Engine.Decide(domain, sub)
	} else {
		dec = filtering.Decision{Reason: filtering.ReasonAllowedDefault}
	}
	ev.Blocked = dec.Blocked
	ev.Reason = string(dec.Reason)

	if dec.Blocked {
		s.blocked.Add(1)
		m := s.blockedReply(r, q)
		ev.RCode, ev.RCodeName = m.Rcode, dns.RcodeToString[m.Rcode]
		_ = w.WriteMsg(m)
		return
	}

	// Cache.
	if s.opts.Cache != nil {
		if m := s.opts.Cache.Get(domain, q.Qtype); m != nil {
			m.Id = r.Id
			m.Response = true
			ev.Cached = true
			ev.RCode, ev.RCodeName = m.Rcode, dns.RcodeToString[m.Rcode]
			_ = w.WriteMsg(m)
			return
		}
	}

	// Forward upstream — a group upstream override wins over the default pool.
	up := s.opts.Upstream
	if s.opts.ResolverFor != nil {
		if u := s.opts.ResolverFor(sub.GroupID); u != nil {
			up = u
		}
	}
	if up == nil {
		s.failures.Add(1)
		ev.Reason = "no upstream configured"
		m := new(dns.Msg).SetRcode(r, dns.RcodeServerFailure)
		ev.RCode, ev.RCodeName = m.Rcode, dns.RcodeToString[m.Rcode]
		_ = w.WriteMsg(m)
		return
	}
	req := r
	if s.dnssec.Load() {
		req = r.Copy()
		req.SetEdns0(4096, true)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	upStart := time.Now()
	resp, err := up.Exchange(ctx, req)
	ev.UpstreamMs = float64(time.Since(upStart)) / float64(time.Millisecond)
	if s.dnssec.Load() && resp != nil {
		if resp.AuthenticatedData {
			ev.DNSSEC = "authenticated"
		} else {
			ev.DNSSEC = "unsigned"
		}
	}
	if err != nil {
		s.failures.Add(1)
		ev.Reason = string(filtering.ReasonUpstreamFailure)
		m := new(dns.Msg).SetRcode(r, dns.RcodeServerFailure)
		ev.RCode, ev.RCodeName = m.Rcode, dns.RcodeToString[m.Rcode]
		_ = w.WriteMsg(m)
		return
	}
	resp.Id = r.Id
	if s.opts.Cache != nil {
		s.opts.Cache.Store(r, resp)
	}
	ev.RCode, ev.RCodeName = resp.Rcode, dns.RcodeToString[resp.Rcode]
	if err := w.WriteMsg(resp); err != nil {
		s.log.Debug("write response failed", "err", err)
	}
}

// blockedReply synthesizes the configured blocking response.
func (s *Server) blockedReply(r *dns.Msg, q dns.Question) *dns.Msg {
	if s.blockMode.Load() == 1 { // null IP mode
		m := new(dns.Msg).SetReply(r)
		m.RecursionAvailable = true
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4zero,
			}}
		case dns.TypeAAAA:
			m.Answer = []dns.RR{&dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP("::"),
			}}
		default:
			// NODATA: NOERROR with empty answer is the correct null-style
			// answer for non-address query types.
		}
		return m
	}
	m := new(dns.Msg).SetRcode(r, dns.RcodeNameError)
	m.RecursionAvailable = true
	return m
}

func (s *Server) trusted(ip netip.Addr) bool {
	if len(s.opts.Trusted) == 0 {
		return false // fail closed: no trusted ranges configured
	}
	for _, p := range s.opts.Trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(a net.Addr) (netip.Addr, bool) {
	// Unmap IPv4-mapped IPv6 addresses: a dual-stack [::] listener reports
	// LAN clients as ::ffff:a.b.c.d, which never matches an IPv4 trusted CIDR.
	unmap := func(ip net.IP) (netip.Addr, bool) {
		addr, ok := netip.AddrFromSlice(ip)
		return addr.Unmap(), ok
	}
	switch v := a.(type) {
	case *net.UDPAddr:
		return unmap(v.IP)
	case *net.TCPAddr:
		return unmap(v.IP)
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	return ip, err == nil
}

// CheckPort reports whether a UDP+TCP bind on addr would currently succeed.
func CheckPort(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("udp: %w", err)
	}
	pc.Close()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return err
		}
		return fmt.Errorf("tcp: %w", err)
	}
	l.Close()
	return nil
}
