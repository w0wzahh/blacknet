package localdns

import (
	"testing"

	"github.com/miekg/dns"
)

func ask(s *Store, name string, t uint16) *dns.Msg {
	return s.Answer(dns.Question{Name: dns.Fqdn(name), Qtype: t, Qclass: dns.ClassINET})
}

func TestARecord(t *testing.T) {
	s := NewStore([]Record{
		{Name: "nas.lan", Type: "A", Value: "192.168.1.10", TTL: 300, Enabled: true},
	})
	m := ask(s, "nas.lan", dns.TypeA)
	if m == nil || len(m.Answer) != 1 {
		t.Fatal("expected an answer")
	}
	a := m.Answer[0].(*dns.A)
	if a.A.String() != "192.168.1.10" {
		t.Fatalf("wrong ip: %v", a.A)
	}
	// Case-insensitive + trailing-dot robust (Fqdn already applied).
	if ask(s, "NAS.LAN", dns.TypeA) == nil {
		t.Fatal("lookup should be case-insensitive")
	}
	// Wrong qtype -> authoritative NODATA (name exists, type doesn't).
	m2 := ask(s, "nas.lan", dns.TypeAAAA)
	if m2 == nil {
		t.Fatal("expected NODATA response, got nil")
	}
	if len(m2.Answer) != 0 || m2.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected empty NOERROR, got %v", m2)
	}
}

func TestWildcard(t *testing.T) {
	s := NewStore([]Record{
		{Name: "*.svc.lan", Type: "A", Value: "10.0.0.1", TTL: 60, Enabled: true},
	})
	if ask(s, "api.svc.lan", dns.TypeA) == nil {
		t.Fatal("wildcard should match one level")
	}
	if ask(s, "other.lan", dns.TypeA) != nil {
		t.Fatal("wildcard should not match sibling")
	}
}

func TestPTRReverse(t *testing.T) {
	s := NewStore([]Record{
		{Name: "10.1.168.192.in-addr.arpa", Type: "PTR", Value: "nas.lan", TTL: 300, Enabled: true},
	})
	m := ask(s, "10.1.168.192.in-addr.arpa", dns.TypePTR)
	if m == nil || len(m.Answer) != 1 {
		t.Fatal("expected PTR answer")
	}
	ptr := m.Answer[0].(*dns.PTR)
	if ptr.Ptr != "nas.lan." {
		t.Fatalf("wrong ptr: %v", ptr.Ptr)
	}
}

func TestCNAMEChain(t *testing.T) {
	s := NewStore([]Record{
		{Name: "alias.lan", Type: "CNAME", Value: "nas.lan", TTL: 300, Enabled: true},
		{Name: "nas.lan", Type: "A", Value: "192.168.1.10", TTL: 300, Enabled: true},
	})
	m := ask(s, "alias.lan", dns.TypeA)
	if m == nil || len(m.Answer) != 2 {
		t.Fatalf("expected CNAME + A, got %v", m)
	}
	if _, ok := m.Answer[0].(*dns.CNAME); !ok {
		t.Fatal("first answer should be CNAME")
	}
	if _, ok := m.Answer[1].(*dns.A); !ok {
		t.Fatal("chained A should follow")
	}
}

func TestDisabledAndEmpty(t *testing.T) {
	s := NewStore([]Record{
		{Name: "off.lan", Type: "A", Value: "10.0.0.1", Enabled: false},
	})
	if ask(s, "off.lan", dns.TypeA) != nil {
		t.Fatal("disabled record must not answer")
	}
	empty := NewStore(nil)
	if ask(empty, "anything", dns.TypeA) != nil {
		t.Fatal("empty store must not answer")
	}
}
