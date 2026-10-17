package dhcp

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestParseAndReply(t *testing.T) {
	// Build a DISCOVER via Reply hack then re-parse it.
	p := &Packet{Op: opRequest, XID: 1234, Flags: bcastFlag, CHAddr: net.HardwareAddr{1, 2, 3, 4, 5, 6}}
	raw := p.Reply(msgDiscover, net.IPv4zero, net.IPv4zero, 0, nil, nil, nil)
	raw[0] = opRequest
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.XID != 1234 || got.MsgType() != msgDiscover {
		t.Fatalf("bad parse: xid=%d type=%d", got.XID, got.MsgType())
	}
	// Garbage must error, not panic.
	if _, err := Parse([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short packet")
	}
	if _, err := Parse(make([]byte, 240)); err == nil {
		t.Fatal("expected error for bad cookie")
	}
}

func TestConfigValidate(t *testing.T) {
	ok := Config{
		InterfaceIP: "192.168.1.2", PoolStart: "192.168.1.100", PoolEnd: "192.168.1.200",
		Mask: "255.255.255.0", Gateway: "192.168.1.1", LeaseSecs: 3600,
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := []Config{
		{InterfaceIP: "10.0.0.2", PoolStart: "192.168.1.100", PoolEnd: "192.168.1.200", Mask: "255.255.255.0", Gateway: "192.168.1.1", LeaseSecs: 3600},    // pool outside subnet
		{InterfaceIP: "192.168.1.2", PoolStart: "192.168.1.2", PoolEnd: "192.168.1.200", Mask: "255.255.255.0", Gateway: "192.168.1.1", LeaseSecs: 3600},   // pool includes server
		{InterfaceIP: "192.168.1.2", PoolStart: "192.168.1.200", PoolEnd: "192.168.1.100", Mask: "255.255.255.0", Gateway: "192.168.1.1", LeaseSecs: 3600}, // reversed
		{InterfaceIP: "192.168.1.2", PoolStart: "192.168.1.100", PoolEnd: "192.168.1.200", Mask: "255.255.0.255", Gateway: "192.168.1.1", LeaseSecs: 3600}, // non-contiguous
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("bad config %d accepted", i)
		}
	}
}

type memStore struct{ ls map[string]Lease }

func (m *memStore) LoadLeases(ctx context.Context) ([]Lease, error) {
	out := make([]Lease, 0, len(m.ls))
	for _, l := range m.ls {
		out = append(out, l)
	}
	return out, nil
}
func (m *memStore) SaveLease(ctx context.Context, l Lease) error { m.ls[l.MAC] = l; return nil }
func (m *memStore) DeleteLease(ctx context.Context, mac string) error {
	delete(m.ls, mac)
	return nil
}

func TestAllocator(t *testing.T) {
	cfg := Config{
		InterfaceIP: "192.168.1.2", PoolStart: "192.168.1.100", PoolEnd: "192.168.1.102",
		Mask: "255.255.255.0", Gateway: "192.168.1.1", LeaseSecs: 3600,
	}
	s, err := New(cfg, &memStore{ls: map[string]Lease{}})
	if err != nil {
		t.Fatal(err)
	}
	s.leases["aa:bb:cc:dd:ee:01"] = Lease{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.100", ExpiresAt: time.Now().Add(time.Hour)}
	s.ipmap["192.168.1.100"] = "aa:bb:cc:dd:ee:01"

	// Existing lease is re-offered.
	if got := s.offerIP("aa:bb:cc:dd:ee:01", nil); got != "192.168.1.100" {
		t.Fatalf("reoffer failed: %s", got)
	}
	// Next free address.
	if got := s.offerIP("aa:bb:cc:dd:ee:02", nil); got != "192.168.1.101" {
		t.Fatalf("alloc failed: %s", got)
	}
	s.ipmap["192.168.1.101"] = "aa:bb:cc:dd:ee:02"
	// Honored request when free.
	if got := s.offerIP("aa:bb:cc:dd:ee:03", net.ParseIP("192.168.1.102")); got != "192.168.1.102" {
		t.Fatalf("requested ip not honored: %s", got)
	}
	s.ipmap["192.168.1.102"] = "aa:bb:cc:dd:ee:03"
	// Pool exhausted.
	if got := s.offerIP("aa:bb:cc:dd:ee:04", nil); got != "" {
		t.Fatalf("expected exhaustion, got %s", got)
	}
}
