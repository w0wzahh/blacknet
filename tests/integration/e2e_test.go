// Package integration exercises a complete Blacknet deployment end to end:
// real DNS server, real upstream mock, real SQLite, real HTTP API.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/emre/blacknet/internal/api"
	"github.com/emre/blacknet/internal/app"
	"github.com/emre/blacknet/internal/auth"
	"github.com/emre/blacknet/internal/config"
)

// mockUpstream is a local DNS server that answers everything with 203.0.113.1.
func startMockUpstream(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg).SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("203.0.113.1").To4(),
			}}
		}
		w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func freeUDPPort(t *testing.T) int {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func dnsQuery(t *testing.T, addr, name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("dns %s: %v", name, err)
	}
	return resp
}

func apiReq(t *testing.T, base, method, path, body string) (*http.Response, string) {
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req, _ := http.NewRequest(method, base+path, rdr)
	req.Header.Set("Authorization", "Bearer testtok")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	buf := new(strings.Builder)
	b := make([]byte, 1<<16)
	for {
		n, err := resp.Body.Read(b)
		buf.Write(b[:n])
		if err != nil {
			break
		}
	}
	resp.Body.Close()
	return resp, buf.String()
}

func TestEndToEnd(t *testing.T) {
	upAddr := startMockUpstream(t)
	dnsPort := freeUDPPort(t)
	dnsAddr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	dir := t.TempDir()

	cfg := config.Default()
	cfg.DataDir = dir
	cfg.DNS.Listen = []string{dnsAddr}
	cfg.DNS.TrustedCIDRs = []string{"127.0.0.0/8"}
	cfg.Web.Listen = "127.0.0.1:0"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	a, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Shutdown(context.Background())

	// Point upstream at our mock instead of the internet.
	ctx := context.Background()
	if _, err := a.DB.SQL.ExecContext(ctx, `UPDATE upstreams SET address=?, enabled=1`, upAddr); err != nil {
		t.Fatal(err)
	}
	if err := a.ReloadUpstreams(ctx); err != nil {
		t.Fatal(err)
	}

	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}

	am := auth.New("testtok")
	apiSrv := api.New(api.Deps{
		Cfg: cfg, DB: a.DB, Engine: a.Engine, DNS: a.DNS, Pool: a.Pool,
		Cache: a.Cache, Lists: a.Lists, Bus: a.Bus, QLog: a.QLog,
		Auth: am, App: a, Version: "e2e",
	})
	httpSrv := httptest.NewServer(apiSrv.Handler())
	defer httpSrv.Close()
	base := httpSrv.URL

	// 1. Allowed domain forwards upstream.
	resp := dnsQuery(t, dnsAddr, "allowed.example")
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("allowed query failed: %v", resp)
	}

	// 2. Add a custom block rule, then the domain must NXDOMAIN.
	rs, body := apiReq(t, base, "POST", "/api/v1/rules",
		`{"domain":"ads.e2e","action":"block","scope":"tree"}`)
	if rs.StatusCode != 201 {
		t.Fatalf("add rule: %s %s", rs.Status, body)
	}
	resp = dnsQuery(t, dnsAddr, "sub.ads.e2e")
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}

	// 3. Give the async logger a moment, then check the query log API.
	time.Sleep(800 * time.Millisecond)
	rs, body = apiReq(t, base, "GET", "/api/v1/queries?blocked=true", "")
	if rs.StatusCode != 200 {
		t.Fatalf("queries: %s", rs.Status)
	}
	if !strings.Contains(body, "sub.ads.e2e") {
		t.Fatalf("blocked query missing from log: %s", body)
	}

	// 4. Stats reflect real data.
	rs, body = apiReq(t, base, "GET", "/api/v1/stats/summary?window=1h", "")
	var sum struct {
		Total   int64 `json:"total_queries"`
		Blocked int64 `json:"blocked_queries"`
	}
	json.Unmarshal([]byte(body), &sum)
	if sum.Total < 2 || sum.Blocked < 1 {
		t.Fatalf("bad summary: %s", body)
	}

	// 5. Allow rule overrides: replace block with allow, query resolves.
	rs, body = apiReq(t, base, "GET", "/api/v1/rules", "")
	var rules []struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal([]byte(body), &rules)
	for _, r := range rules {
		apiReq(t, base, "DELETE", fmt.Sprintf("/api/v1/rules/%d", r.ID), "")
	}
	rs, _ = apiReq(t, base, "POST", "/api/v1/rules",
		`{"domain":"ads.e2e","action":"allow","scope":"tree"}`)
	if rs.StatusCode != 201 {
		t.Fatalf("allow rule: %s", rs.Status)
	}
	a.Cache.Flush()
	resp = dnsQuery(t, dnsAddr, "sub.ads.e2e")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("allow rule should have unblocked, got %s", dns.RcodeToString[resp.Rcode])
	}

	// 6. Restart: reopen the app on the same data dir and confirm persistence.
	a.Shutdown(context.Background())
	a2, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Shutdown(context.Background())
	rules2, err := a2.DB.ListRules(ctx)
	if err != nil || len(rules2) != 1 || rules2[0].Action != "allow" {
		t.Fatalf("rules not persisted after restart: %+v err=%v", rules2, err)
	}
	clients, _ := a2.DB.ListClients(ctx)
	if len(clients) == 0 {
		t.Fatal("clients not persisted")
	}
	_ = netip.IPv6Unspecified // keep import used
}
