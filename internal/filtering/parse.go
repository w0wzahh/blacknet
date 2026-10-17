package filtering

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

const (
	maxLineLen  = 2048
	maxListSize = 10_000_000
)

// ParseResult is the output of parsing a downloaded blocklist.
type ParseResult struct {
	// Blocks are domains that should be blocked (tree match).
	Blocks map[string]struct{}
	// Allows are adblock-style @@ exception domains.
	Allows map[string]struct{}
	// Skipped counts lines that were comments, invalid, or unsupported.
	Skipped int
	// Total counts non-empty lines examined.
	Total int
	// Truncated is true when the entry cap was hit.
	Truncated bool
}

// ParseList parses common blocklist formats into domain sets. Supported:
//   - hosts-file lines: "0.0.0.0 ads.example.com" (also 127.0.0.1, ::)
//   - adblock rules: "||ads.example.com^" and "@@||ok.ads.example.com^"
//   - plain domain lists: "ads.example.com"
//
// Comments (#, !, //), cosmetic filters (##, #@#, #?#), script injections and
// any non-domain content are ignored. Everything is treated as untrusted
// input: nothing is executed, and only syntactically valid domains are kept.
func ParseList(r io.Reader) *ParseResult {
	res := &ParseResult{
		Blocks: make(map[string]struct{}),
		Allows: make(map[string]struct{}),
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLineLen)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimPrefix(line, string([]byte{0xEF, 0xBB, 0xBF})) // strip UTF-8 BOM
		if line == "" {
			continue
		}
		res.Total++
		if len(res.Blocks)+len(res.Allows) >= maxListSize {
			res.Truncated = true
			break
		}
		parseLine(line, res)
	}
	return res
}

func parseLine(line string, res *ParseResult) {
	// Comments and cosmetic/element rules.
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") ||
		strings.HasPrefix(line, "//") || strings.HasPrefix(line, "[") {
		res.Skipped++
		return
	}
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.Contains(line, "#?#") {
		res.Skipped++
		return
	}

	// Adblock exception: @@||domain^
	if strings.HasPrefix(line, "@@") {
		if d, ok := parseAdblock(strings.TrimPrefix(line, "@@")); ok {
			res.Allows[d] = struct{}{}
			return
		}
		res.Skipped++
		return
	}

	// Adblock domain rule: ||domain^ optionally followed by $options.
	if strings.HasPrefix(line, "||") {
		if d, ok := parseAdblock(line); ok {
			res.Blocks[d] = struct{}{}
			return
		}
		res.Skipped++
		return
	}
	// Other adblock URL patterns (|http://, single |, regex /.../) are not
	// domain rules; skip rather than guess.
	if strings.HasPrefix(line, "|") || strings.HasPrefix(line, "/") {
		res.Skipped++
		return
	}

	// Hosts-file or plain domain line. Split fields; an optional inline
	// comment starts with '#'.
	fields := strings.Fields(line)
	if len(fields) == 0 {
		res.Skipped++
		return
	}
	var domains []string
	if _, err := netip.ParseAddr(fields[0]); err == nil {
		// hosts line: first field is an IP, the rest are hostnames.
		domains = fields[1:]
		if len(domains) == 0 {
			res.Skipped++
			return
		}
	} else {
		domains = fields[:1]
	}
	added := false
	for _, d := range domains {
		if strings.HasPrefix(d, "#") {
			break // inline comment
		}
		d = Normalize(strings.TrimPrefix(d, "*."))
		if !IsValidDomain(d) || isLocalOrIP(d) {
			continue
		}
		res.Blocks[d] = struct{}{}
		added = true
	}
	if !added {
		res.Skipped++
	}
}

// parseAdblock extracts the domain from a "||domain^..." adblock rule.
func parseAdblock(s string) (string, bool) {
	s = strings.TrimPrefix(s, "||")
	if i := strings.IndexAny(s, "^$"); i >= 0 {
		s = s[:i]
	}
	s = Normalize(strings.TrimPrefix(s, "*."))
	if !IsValidDomain(s) || isLocalOrIP(s) {
		return "", false
	}
	return s, true
}

func isLocalOrIP(d string) bool {
	if _, err := netip.ParseAddr(d); err == nil {
		return true
	}
	switch d {
	case "localhost", "localhost.localdomain", "local", "home.arpa",
		"broadcasthost", "ip6-localhost", "ip6-loopback":
		return true
	}
	return false
}
