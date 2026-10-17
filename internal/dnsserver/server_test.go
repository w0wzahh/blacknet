package dnsserver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/w0wzahh/blacknet/internal/cache"
	"github.com/w0wzahh/blacknet/internal/filtering"
	"github.com/w0wzahh/blacknet/internal/upstream"
)

// startMockUpstream starts a real DNS server that answers A queries with
// 93.184.216.34 and tracks which domains it saw.
type mockUpstream struct {
	addr string
	srv  *dns.Server
	mu   sync.Mutex
	seen []string
}

func startMockUpstream(t *testing.T) *mockUpstream {
	t.Helper()
	mu := &mockUpstream{}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mu.addr = pc.LocalAddr().String()
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		mu.mu.Lock()
		if len(r.Question) > 0 {
			mu.seen = append(mu.seen, r.Question[0].Name)
		}
		mu.mu.Unlock()
		m := new(dns.Msg).SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("93.184.216.34").To4(),
			}}
		}
		w.WriteMsg(m)
	})
	mu.srv = &dns.Server{PacketConn: pc, Handler: h}
	go mu.srv.ActivateAndServe()
	t.Cleanup(func() { mu.srv.Shutdown() })
	return mu
}

func (m *mockUpstream) sawDomain(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.seen {
		if s == name {
			return true
		}
	}
	return false
}

func startTestServer(t *testing.T, e *filtering.Engine, pool *upstream.Pool) (addr string, events *[]QueryEvent) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	addr = fmt.Sprintf("127.0.0.1:%d", port)
	var mu sync.Mutex
	evs := []QueryEvent{}
	srv := New(Options{
		Addrs:    []string{addr},
		Trusted:  []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Engine:   e,
		Upstream: pool,
		Cache:    cache.New(1000, 0, time.Hour, time.Minute),
		Publish: func(ev QueryEvent) {
			mu.Lock()
			evs = append(evs, ev)
			mu.Unlock()
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("start dns server: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	return addr, &evs
}

func query(t *testing.T, addr, name string, qtype uint16, net_ string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	c := &dns.Client{Net: net_, Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return resp
}

func TestBlockedDomainNXDOMAIN(t *testing.T) {
	up := startMockUpstream(t)
	e := filtering.NewEngine()
	e.Replace(filtering.Snapshot{Blocks: map[string]int64{"ads.test": 1}})
	pool, _ := upstream.NewPool([]upstream.Config{{
		ID: 1, Protocol: upstream.ProtoUDP, Address: up.addr, Timeout: 2 * time.Second, Enabled: true,
	}}, false)
	addr, _ := startTestServer(t, e, pool)

	resp := query(t, addr, "ads.test", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}
	// Blocked query must never reach upstream.
	time.Sleep(50 * time.Millisecond)
	if up.sawDomain("ads.test.") {
		t.Fatal("blocked domain leaked to upstream")
	}
}

func TestBlockedNullMode(t *testing.T) {
	up := startMockUpstream(t)
	e := filtering.NewEngine()
	e.Replace(filtering.Snapshot{Blocks: map[string]int64{"ads.test": 1}})
	pool, _ := upstream.NewPool([]upstream.Config{{
		ID: 1, Protocol: upstream.ProtoUDP, Address: up.addr, Timeout: 2 * time.Second, Enabled: true,
	}}, false)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	pc.Close()
	srv := New(Options{
		Addrs: []string{addr}, Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Engine: e, Upstream: pool, Cache: cache.New(100, 0, time.Hour, time.Minute),
	})
	srv.SetBlockingMode(ModeNullIP)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	resp := query(t, addr, "ads.test", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("expected null A answer, got %v", resp)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || !a.A.IsUnspecified() {
		t.Fatalf("expected 0.0.0.0, got %v", resp.Answer[0])
	}
	resp6 := query(t, addr, "ads.test", dns.TypeAAAA, "udp")
	if resp6.Rcode != dns.RcodeSuccess || len(resp6.Answer) != 1 {
		t.Fatalf("expected null AAAA answer, got %v", resp6)
	}
	// Non-address type under null mode -> NODATA.
	respTxt := query(t, addr, "ads.test", dns.TypeTXT, "udp")
	if respTxt.Rcode != dns.RcodeSuccess || len(respTxt.Answer) != 0 {
		t.Fatalf("expected NODATA for TXT, got %v", respTxt)
	}
}

func TestAllowedForwardedUDPAndTCP(t *testing.T) {
	up := startMockUpstream(t)
	e := filtering.NewEngine()
	pool, _ := upstream.NewPool([]upstream.Config{{
		ID: 1, Protocol: upstream.ProtoUDP, Address: up.addr, Timeout: 2 * time.Second, Enabled: true,
	}}, false)
	addr, _ := startTestServer(t, e, pool)

	for _, proto := range []string{"udp", "tcp"} {
		resp := query(t, addr, "good.test", dns.TypeA, proto)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("%s: expected A answer, got %v", proto, resp)
		}
	}
	if !up.sawDomain("good.test.") {
		t.Fatal("upstream never saw allowed query")
	}
}

func TestAllowRuleOverridesBlocklistLive(t *testing.T) {
	up := startMockUpstream(t)
	e := filtering.NewEngine()
	e.Replace(filtering.Snapshot{Blocks: map[string]int64{"ads.test": 1}})
	pool, _ := upstream.NewPool([]upstream.Config{{
		ID: 1, Protocol: upstream.ProtoUDP, Address: up.addr, Timeout: 2 * time.Second, Enabled: true,
	}}, false)
	addr, _ := startTestServer(t, e, pool)

	if resp := query(t, addr, "ads.test", dns.TypeA, "udp"); resp.Rcode != dns.RcodeNameError {
		t.Fatal("expected block")
	}
	// Rule change without restart.
	e.Replace(filtering.Snapshot{
		Rules: []filtering.Rule{{
			ID: 1, Domain: "ads.test", Action: filtering.ActionAllow, Scope: filtering.ScopeExact, Enabled: true,
		}},
		Blocks: map[string]int64{"ads.test": 1},
	})
	resp := query(t, addr, "ads.test", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatal("expected resolution after allow rule")
	}
}

func TestUpstreamFailover(t *testing.T) {
	up := startMockUpstream(t)
	e := filtering.NewEngine()
	pool, _ := upstream.NewPool([]upstream.Config{
		{ID: 1, Protocol: upstream.ProtoUDP, Address: "127.0.0.1:1", Timeout: 500 * time.Millisecond, Enabled: true, Priority: 0},
		{ID: 2, Protocol: upstream.ProtoUDP, Address: up.addr, Timeout: 2 * time.Second, Enabled: true, Priority: 1},
	}, false)
	addr, _ := startTestServer(t, e, pool)
	resp := query(t, addr, "failover.test", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatal("expected failover to second upstream")
	}
}

func TestUpstreamAllDownSERVFAIL(t *testing.T) {
	e := filtering.NewEngine()
	pool, _ := upstream.NewPool([]upstream.Config{
		{ID: 1, Protocol: upstream.ProtoUDP, Address: "127.0.0.1:1", Timeout: 300 * time.Millisecond, Enabled: true},
	}, false)
	addr, evs := startTestServer(t, e, pool)
	resp := query(t, addr, "down.test", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got %v", resp.Rcode)
	}
	found := false
	for _, ev := range *evs {
		if ev.Domain == "down.test" && ev.Reason == string(filtering.ReasonUpstreamFailure) {
			found = true
		}
	}
	if !found {
		t.Fatal("upstream failure not logged correctly")
	}
}

func TestUntrustedClientRefused(t *testing.T) {
	up := startMockUpstream(t)
	e := filtering.NewEngine()
	pool, _ := upstream.NewPool([]upstream.Config{{
		ID: 1, Protocol: upstream.ProtoUDP, Address: up.addr, Timeout: 2 * time.Second, Enabled: true,
	}}, false)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	pc.Close()
	// Trusted range does not include 127.0.0.1.
	srv := New(Options{
		Addrs: []string{addr}, Trusted: []netip.Prefix{netip.MustParsePrefix("10.9.9.0/24")},
		Engine: e, Upstream: pool,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())
	resp := query(t, addr, "x.test", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED, got %v", resp.Rcode)
	}
}

func TestMalformedPacket(t *testing.T) {
	up := startMockUpstream(t)
	e := filtering.NewEngine()
	pool, _ := upstream.NewPool([]upstream.Config{{
		ID: 1, Protocol: upstream.ProtoUDP, Address: up.addr, Timeout: 2 * time.Second, Enabled: true,
	}}, false)
	addr, _ := startTestServer(t, e, pool)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	conn.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00}) // garbage
	// Server should not crash; a normal query still works afterwards.
	resp := query(t, addr, "still.test", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatal("server unhealthy after malformed packet")
	}
}

func TestConcurrentQueries(t *testing.T) {
	up := startMockUpstream(t)
	e := filtering.NewEngine()
	e.Replace(filtering.Snapshot{Blocks: map[string]int64{"ads.test": 1}})
	pool, _ := upstream.NewPool([]upstream.Config{{
		ID: 1, Protocol: upstream.ProtoUDP, Address: up.addr, Timeout: 2 * time.Second, Enabled: true,
	}}, false)
	addr, _ := startTestServer(t, e, pool)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				query(t, addr, "ads.test", dns.TypeA, "udp")
			} else {
				query(t, addr, fmt.Sprintf("q%d.test", i), dns.TypeA, "udp")
			}
		}(i)
	}
	wg.Wait()
}
