// Package localdns serves user-defined local DNS records (A, AAAA, CNAME,
// TXT, PTR). Records answer authoritatively before filtering and upstream
// forwarding — they are precedence level 0 and are never blocked by rules.
//
// Wildcard owners ("*.lan.example") match exactly one label below the apex
// (per RFC 4592 semantics: the wildcard covers names where the apex has no
// exact records — implemented here as suffix matching when no exact record
// exists, which is the practical behaviour users expect on a LAN).
package localdns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"github.com/w0wzahh/blacknet/internal/filtering"
)

// Supported record types.
var validTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "TXT": true, "PTR": true,
}

// Record is one local DNS entry.
type Record struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"` // owner; leading "*." allowed
	Type      string `json:"type"` // A | AAAA | CNAME | TXT | PTR
	Value     string `json:"value"`
	TTL       int    `json:"ttl"`
	Enabled   bool   `json:"enabled"`
	Comment   string `json:"comment"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// Validate checks a record for syntax and internal consistency; warnings are
// returned separately (e.g. shadowing a public domain) for the UI to surface.
func (r *Record) Validate() (errs map[string]string, warnings []string) {
	errs = map[string]string{}
	r.Name = filtering.Normalize(r.Name)
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Value = strings.TrimSpace(r.Value)

	if strings.HasPrefix(r.Name, "*.") {
		if !filtering.IsValidDomain(r.Name[2:]) {
			errs["name"] = "invalid wildcard name"
		}
	} else if !validOwner(r.Name) {
		errs["name"] = "invalid DNS name (use lowercase host name or a reverse zone name)"
	}
	if !validTypes[r.Type] {
		errs["type"] = "type must be A, AAAA, CNAME, TXT or PTR"
	}
	switch r.Type {
	case "A":
		ip, err := netip.ParseAddr(r.Value)
		if err != nil || !ip.Is4() {
			errs["value"] = "A record requires an IPv4 address"
		}
	case "AAAA":
		ip, err := netip.ParseAddr(r.Value)
		if err != nil || !ip.Is6() {
			errs["value"] = "AAAA record requires an IPv6 address"
		}
	case "CNAME", "PTR":
		if !filtering.IsValidDomain(r.Value) {
			errs["value"] = r.Type + " requires a valid target name"
		}
		r.Value = filtering.Normalize(r.Value)
	case "TXT":
		if len(r.Value) > 255 {
			errs["value"] = "TXT value limited to 255 characters"
		}
	}
	if r.TTL < 0 || r.TTL > 86400*7 {
		errs["ttl"] = "ttl must be 0-604800 seconds"
	}
	// Warning (not an error): shadowing a well-known public domain.
	if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" {
		if looksPublic(r.Name) {
			warnings = append(warnings,
				fmt.Sprintf("%q looks like a public domain — this record overrides real resolution for all clients", r.Name))
		}
	}
	return errs, warnings
}

// validOwner accepts a DNS name or a reverse (in-addr.arpa / ip6.arpa) name.
func validOwner(name string) bool {
	if filtering.IsValidDomain(name) {
		return true
	}
	// Reverse zones contain hex digits with dots — still valid domain syntax,
	// so IsValidDomain covers them; this hook documents the intent.
	return false
}

// looksPublic is a heuristic: a name is "local" when it sits under a
// conventional LAN suffix or a reverse zone, otherwise we warn.
func looksPublic(name string) bool {
	localSuffixes := []string{
		".lan", ".local", ".home", ".internal", ".intranet", ".corp",
		".home.arpa", ".lan.arpa", ".in-addr.arpa", ".ip6.arpa",
	}
	if !strings.Contains(name, ".") {
		return false // single-label host names are local by convention
	}
	for _, s := range localSuffixes {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	return true
}

// Store is an immutable record set.
type Store struct {
	// exact[owner] -> records; wildcard[apex] -> records
	exact    map[string][]Record
	wildcard map[string][]Record
}

// NewStore builds a store from enabled records.
func NewStore(records []Record) *Store {
	s := &Store{exact: map[string][]Record{}, wildcard: map[string][]Record{}}
	for _, r := range records {
		if !r.Enabled {
			continue
		}
		name := filtering.Normalize(r.Name)
		if strings.HasPrefix(name, "*.") {
			s.wildcard[name[2:]] = append(s.wildcard[name[2:]], r)
		} else {
			s.exact[name] = append(s.exact[name], r)
		}
	}
	return s
}

// Records returns all records matching owner name (exact or one wildcard).
func (s *Store) Records(name string) []Record {
	name = filtering.Normalize(name)
	if rs, ok := s.exact[name]; ok {
		return rs
	}
	// Wildcard: "*.apex" matches labels strictly below apex.
	if i := strings.IndexByte(name, '.'); i > 0 {
		if rs, ok := s.wildcard[name[i+1:]]; ok {
			return rs
		}
	}
	return nil
}

// Answer builds a response for q, or nil when nothing local applies.
// CNAME targets are resolved locally (depth-bounded); if the chain escapes
// the local store the CNAME alone is returned and the client re-queries the
// target through the normal pipeline.
func (s *Store) Answer(q dns.Question) *dns.Msg {
	name := filtering.Normalize(q.Name)
	if name == "" {
		return nil
	}
	recs := s.Records(name)
	if len(recs) == 0 {
		return nil
	}
	msg := new(dns.Msg)
	msg.Response = true
	msg.RecursionAvailable = true
	msg.SetQuestion(q.Name, q.Qtype)

	answered := false
	cur := name
	for depth := 0; depth < 8; depth++ {
		rs := s.Records(cur)
		if len(rs) == 0 {
			break
		}
		var cname *Record
		for i := range rs {
			r := &rs[i]
			if int16Match(r.Type, q.Qtype) || r.Type == "CNAME" {
				if rr := buildRR(cur, *r); rr != nil {
					msg.Answer = append(msg.Answer, rr)
					answered = answered || int16Match(r.Type, q.Qtype)
					if r.Type == "CNAME" && !int16Match(r.Type, q.Qtype) {
						cname = r
					}
				}
			}
		}
		if cname != nil {
			cur = cname.Value
			continue
		}
		break
	}
	if !answered && len(msg.Answer) == 0 {
		// Records exist for the name but none match qtype → authoritative
		// NODATA (NOERROR, empty answer) rather than falling to upstream.
		msg.Rcode = dns.RcodeSuccess
		return msg
	}
	msg.Rcode = dns.RcodeSuccess
	return msg
}

func int16Match(rt string, qt uint16) bool {
	t, ok := dns.StringToType[rt]
	return ok && t == qt
}

func buildRR(owner string, r Record) dns.RR {
	fq := dns.Fqdn(owner)
	hdr := dns.RR_Header{Name: fq, Class: dns.ClassINET, Ttl: uint32(r.TTL)}
	switch r.Type {
	case "A":
		ip, err := netip.ParseAddr(r.Value)
		if err != nil || !ip.Is4() {
			return nil
		}
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: net.IP(ip.AsSlice())}
	case "AAAA":
		ip, err := netip.ParseAddr(r.Value)
		if err != nil || !ip.Is6() {
			return nil
		}
		hdr.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: hdr, AAAA: net.IP(ip.AsSlice())}
	case "CNAME":
		hdr.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(r.Value)}
	case "PTR":
		hdr.Rrtype = dns.TypePTR
		return &dns.PTR{Hdr: hdr, Ptr: dns.Fqdn(r.Value)}
	case "TXT":
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: []string{r.Value}}
	}
	return nil
}

// Conflicts reports problems within a proposed record set: duplicate CNAME
// semantics (CNAME alongside other types at the same owner) and duplicate
// identical records.
func Conflicts(records []Record, candidate *Record) []string {
	var warns []string
	owner := filtering.Normalize(candidate.Name)
	owner = strings.TrimPrefix(owner, "*.")
	for _, r := range records {
		ro := strings.TrimPrefix(filtering.Normalize(r.Name), "*.")
		if r.ID == candidate.ID || ro != owner {
			continue
		}
		if candidate.Type == "CNAME" && r.Type != "CNAME" && r.Enabled {
			warns = append(warns, fmt.Sprintf("CNAME at %s coexists with %s record #%d — clients see inconsistent answers", owner, r.Type, r.ID))
		}
		if candidate.Type != "CNAME" && r.Type == "CNAME" && r.Enabled {
			warns = append(warns, fmt.Sprintf("%s at %s coexists with CNAME record #%d — clients see inconsistent answers", candidate.Type, owner, r.ID))
		}
		if r.Type == candidate.Type && filtering.Normalize(r.Value) == filtering.Normalize(candidate.Value) && r.Enabled {
			warns = append(warns, fmt.Sprintf("duplicates record #%d", r.ID))
		}
	}
	return warns
}
