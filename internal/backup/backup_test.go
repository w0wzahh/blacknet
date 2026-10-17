package backup

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/w0wzahh/blacknet/internal/database"
	"github.com/w0wzahh/blacknet/internal/filtering"
	"github.com/w0wzahh/blacknet/internal/upstream"
)

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	db.SetSetting("settings.blocking_mode", "null")
	db.AddRule(ctx, &filtering.Rule{Domain: "ads.x", Action: filtering.ActionBlock, Scope: filtering.ScopeTree, Enabled: true})
	db.AddUpstream(ctx, &upstream.Config{Name: "cf", Protocol: upstream.ProtoUDP, Address: "1.1.1.1:53", Timeout: 4 * time.Second, Enabled: true})
	if _, err := db.AddBlocklist(ctx, "test", "https://example.com/list.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpsertClientSeen(ctx, "192.168.1.50", true); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Create(ctx, db, &buf, false); err != nil {
		t.Fatal(err)
	}

	mf, counts, err := Inspect(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if mf.Format != "blacknet-backup" || counts["rules.json"] != 1 || counts["clients.json"] != 1 {
		t.Fatalf("manifest %+v counts %+v", mf, counts)
	}

	// Restore into a fresh database.
	db2, err := database.Open(filepath.Join(dir, "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if err := Restore(ctx, db2, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	rules, _ := db2.ListRules(ctx)
	if len(rules) != 1 || rules[0].Domain != "ads.x" || rules[0].Scope != filtering.ScopeTree {
		t.Fatalf("rules not restored: %+v", rules)
	}
	ups, _ := db2.ListUpstreams(ctx)
	if len(ups) != 1 || ups[0].Address != "1.1.1.1:53" {
		t.Fatalf("upstreams not restored: %+v", ups)
	}
	clients, _ := db2.ListClients(ctx)
	if len(clients) != 1 || clients[0].IP != "192.168.1.50" {
		t.Fatalf("clients not restored: %+v", clients)
	}
	var mode string
	if ok, _ := db2.GetSetting("settings.blocking_mode", &mode); !ok || mode != "null" {
		t.Fatalf("settings not restored: %q", mode)
	}
}

func TestRejectNonBackup(t *testing.T) {
	_, _, err := Inspect(bytes.NewReader([]byte("not a zip")), 9)
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
}
