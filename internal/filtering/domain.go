package filtering

import "strings"

// Normalize lowercases a domain, trims whitespace and a trailing root dot.
func Normalize(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimSuffix(d, ".")
	return d
}

// IsValidDomain reports whether d is a syntactically valid DNS host name.
// A leading "*." wildcard label is accepted and treated as a tree-scope marker
// by callers; it is stripped before validation here.
func IsValidDomain(d string) bool {
	d = Normalize(d)
	if strings.HasPrefix(d, "*.") {
		d = d[2:]
	}
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// Parents returns d itself followed by each parent suffix, most specific first.
// e.g. "www.ads.example.com" -> [www.ads.example.com ads.example.com example.com com]
func Parents(d string) []string {
	d = Normalize(d)
	if d == "" {
		return nil
	}
	parts := strings.Split(d, ".")
	out := make([]string, 0, len(parts))
	for i := range parts {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}

// IsSubdomainOf reports whether d equals apex or is a subdomain of it.
func IsSubdomainOf(d, apex string) bool {
	d = Normalize(d)
	apex = Normalize(apex)
	return d == apex || strings.HasSuffix(d, "."+apex)
}
