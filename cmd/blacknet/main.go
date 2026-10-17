// Command blacknet is the Blacknet server and administration CLI.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/w0wzahh/blacknet/internal/api"
	"github.com/w0wzahh/blacknet/internal/app"
	"github.com/w0wzahh/blacknet/internal/auth"
	"github.com/w0wzahh/blacknet/internal/config"
	"github.com/w0wzahh/blacknet/internal/filtering"
	"github.com/w0wzahh/blacknet/internal/logging"
)

var version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "status":
		err = cmdStatus(args)
	case "check-config":
		err = cmdCheckConfig(args)
	case "test-dns":
		err = cmdTestDNS(args)
	case "test-rule":
		err = cmdTestRule(args)
	case "blocklist":
		err = cmdBlocklist(args)
	case "cache":
		err = cmdCache(args)
	case "backup":
		err = cmdBackup(args)
	case "init":
		err = cmdInit(args)
	case "version":
		fmt.Printf("blacknet %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`blacknet — self-hosted network-wide DNS ad blocker

Usage:
  blacknet serve [--config config.yaml]        Run the DNS server + dashboard
  blacknet init [--config config.yaml]         Write an example config file
  blacknet status                              Show service status (needs running server)
  blacknet check-config [--config path]        Validate configuration
  blacknet test-dns <domain> [--server addr]   Send a real DNS query
  blacknet test-rule <domain>                  Evaluate a domain against the rule engine
  blacknet blocklist update [--config path]    Refresh all enabled blocklists
  blacknet cache flush                         Flush the DNS cache (needs running server)
  blacknet backup [--out file.zip]             Download a backup (needs running server)
  blacknet version                             Print version
`)
}

func flagSet(args []string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("blacknet", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to config.yaml")
	fs.Parse(args)
	return fs, cfgPath
}

func cmdServe(args []string) error {
	fs, cfgPath := flagSet(args)
	webListen := fs.String("web", "", "override web listen addr")
	fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	logging.Init(cfg.LogLevel)
	if *webListen != "" {
		cfg.Web.Listen = *webListen
	}
	a, err := app.New(cfg)
	if err != nil {
		return err
	}
	app.Version = version

	tok, err := a.APIToken()
	if err != nil {
		return err
	}
	am := auth.New(tok)
	var hash string
	if ok, _ := a.DB.GetSetting("admin.password_hash", &hash); ok {
		am.LoadHash(hash)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := a.Start(ctx); err != nil {
		return fmt.Errorf("start DNS service: %w (port 53 usually needs administrator/root privileges)", err)
	}

	apiSrv := api.New(api.Deps{
		Cfg: cfg, DB: a.DB, Engine: a.Engine, DNS: a.DNS, Pool: a.Pool,
		Cache: a.Cache, Lists: a.Lists, Bus: a.Bus, QLog: a.QLog,
		Auth: am, App: a, Enf: a.Enf, Version: version, WebRoot: "web/dist",
	})
	apiErr := make(chan error, 1)
	go func() { apiErr <- apiSrv.Start(ctx, cfg.Web.Listen) }()

	fmt.Printf("Blacknet %s\n  DNS:       %v\n  Dashboard: http://%s\n", version, cfg.DNS.Listen, cfg.Web.Listen)

	err = <-apiErr
	stop()
	shutCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	a.Shutdown(shutCtx)
	return err
}

// apiCall talks to a running server's HTTP API using the local token file.
func apiCall(cfg *config.Config, method, path string, body io.Reader) (*http.Response, error) {
	tok, err := os.ReadFile(cfg.TokenPath())
	if err != nil {
		return nil, fmt.Errorf("read api token: %w (is the server running and has it created %s?)", err, cfg.TokenPath())
	}
	url := "http://" + cfg.Web.Listen + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(tok))
	client := &http.Client{Timeout: 15 * time.Second}
	return client.Do(req)
}

func cmdStatus(args []string) error {
	_, cfgPath := flagSet(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	resp, err := apiCall(cfg, "GET", "/api/v1/status", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(pretty))
	return nil
}

func cmdCheckConfig(args []string) error {
	_, cfgPath := flagSet(args)
	p := *cfgPath
	cfg, err := config.Load(p)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	fmt.Println("configuration OK")
	for _, a := range cfg.DNS.Listen {
		fmt.Println("dns listen:", a)
	}
	fmt.Println("web listen:", cfg.Web.Listen)
	fmt.Println("data dir:", cfg.DataDir)
	return nil
}

// splitArgs reorders argv so flags may appear after positional arguments.
// Go's flag package stops at the first non-flag token; this lets users write
// "blacknet test-dns example.com --server 1.2.3.4:53".
func splitArgs(args []string, flagsWithValue map[string]bool) (flagArgs, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") && flagsWithValue[name] && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			positional = append(positional, a)
		}
	}
	return flagArgs, positional
}

func cmdTestDNS(args []string) error {
	fs := flag.NewFlagSet("test-dns", flag.ContinueOnError)
	server := fs.String("server", "", "dns server addr (default: first dns.listen)")
	qtype := fs.String("type", "A", "query type")
	cfgPath := fs.String("config", "", "config path")
	fa, pos := splitArgs(args, map[string]bool{"server": true, "type": true, "config": true})
	fs.Parse(fa)
	if len(pos) < 1 {
		return fmt.Errorf("usage: blacknet test-dns <domain> [--server ip:port] [--type A]")
	}
	domain := pos[0]
	addr := *server
	if addr == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		addr = cfg.DNS.Listen[0]
	}
	t, ok := dns.StringToType[*qtype]
	if !ok {
		return fmt.Errorf("unknown qtype %q", *qtype)
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), t)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 5 * time.Second}
	start := time.Now()
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		return fmt.Errorf("query %s via %s failed: %w", domain, addr, err)
	}
	fmt.Printf("%s %s -> %s (%s)\n", domain, *qtype, dns.RcodeToString[resp.Rcode], time.Since(start).Round(time.Millisecond))
	for _, rr := range resp.Answer {
		fmt.Println("  ", rr.String())
	}
	return nil
}

func cmdTestRule(args []string) error {
	fs, cfgPath := flagSet(args)
	fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: blacknet test-rule <domain>")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	a, err := app.New(cfg)
	if err != nil {
		return err
	}
	defer a.DB.Close()
	domain := filtering.Normalize(fs.Arg(0))
	dec := a.Engine.Decide(domain, filtering.Subject{Now: time.Now()})
	out, _ := json.MarshalIndent(dec, "", "  ")
	fmt.Println(string(out))
	return nil
}

func cmdBlocklist(args []string) error {
	if len(args) == 0 || args[0] != "update" {
		return fmt.Errorf("usage: blacknet blocklist update [--config path]")
	}
	fs, cfgPath := flagSet(args[1:])
	fs.Parse(args[1:])
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	a, err := app.New(cfg)
	if err != nil {
		return err
	}
	defer a.DB.Close()
	res := a.Lists.RefreshAll(context.Background(), 0)
	for _, r := range res {
		fmt.Printf("list %d: %s (%d rules)\n", r.ListID, r.Message, r.RuleCount)
	}
	return nil
}

func cmdCache(args []string) error {
	if len(args) == 0 || args[0] != "flush" {
		return fmt.Errorf("usage: blacknet cache flush")
	}
	fs, cfgPath := flagSet(args[1:])
	fs.Parse(args[1:])
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	resp, err := apiCall(cfg, "POST", "/api/v1/cache/flush", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server: %s %s", resp.Status, string(b))
	}
	fmt.Println("cache flushed")
	return nil
}

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "output file (default blacknet-backup-<ts>.zip)")
	cfgPath := fs.String("config", "", "config path")
	hist := fs.Bool("include-history", false, "include query history")
	fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	url := "/api/v1/backup"
	if *hist {
		url += "?include_history=true"
	}
	resp, err := apiCall(cfg, "POST", url, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server: %s %s", resp.Status, string(b))
	}
	name := *out
	if name == "" {
		name = fmt.Sprintf("blacknet-backup-%s.zip", time.Now().Format("20060102-150405"))
	}
	f, err := os.OpenFile(filepath.Clean(name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	fmt.Println("backup written to", name)
	return nil
}

func cmdInit(args []string) error {
	fs, cfgPath := flagSet(args)
	fs.Parse(args)
	p := *cfgPath
	if p == "" {
		p = "config.yaml"
	}
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("%s already exists", p)
	}
	if err := config.WriteExample(p); err != nil {
		return err
	}
	fmt.Println("wrote", p)
	return nil
}
