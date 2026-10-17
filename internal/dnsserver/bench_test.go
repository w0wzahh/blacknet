package dnsserver

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/w0wzahh/blacknet/internal/cache"
	"github.com/w0wzahh/blacknet/internal/filtering"
	"github.com/w0wzahh/blacknet/internal/upstream"
)

// BenchmarkEndToEnd measures full request handling against a mock upstream:
// rule check + forward + cache.
// Run: go test -bench=. -benchmem ./internal/dnsserver
func BenchmarkBlocked(b *testing.B) {
	e := filtering.NewEngine()
	blocks := map[string]int64{}
	for i := 0; i < 200000; i++ {
		blocks[fmt.Sprintf("ads%d.example", i)] = 1
	}
	e.Replace(nil, blocks, nil)
	srv := New(Options{
		Engine:   e,
		Upstream: &upstream.Pool{},
		Cache:    cache.New(10000, 0, time.Hour, time.Minute),
	})
	srv.SetBlockingMode(ModeNXDomain)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			w := &fakeWriter{remote: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 5300}}
			m := new(dns.Msg)
			m.SetQuestion(fmt.Sprintf("ads%d.example.", i%200000), dns.TypeA)
			srv.ServeDNS(w, m)
			i++
		}
	})
}

// fakeWriter records the written message without network IO.
type fakeWriter struct {
	remote net.Addr
	last   *dns.Msg
}

func (f *fakeWriter) LocalAddr() net.Addr         { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (f *fakeWriter) RemoteAddr() net.Addr        { return f.remote }
func (f *fakeWriter) WriteMsg(m *dns.Msg) error   { f.last = m; return nil }
func (f *fakeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeWriter) Close() error                { return nil }
func (f *fakeWriter) TsigStatus() error           { return nil }
func (f *fakeWriter) TsigTimersOnly(bool)         {}
func (f *fakeWriter) Hijack()                     {}
func (f *fakeWriter) UDPSize() int                { return dns.DefaultMsgSize }
