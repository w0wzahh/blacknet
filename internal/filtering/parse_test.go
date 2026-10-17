package filtering

import (
	"strings"
	"testing"
)

func TestParseHostsFormat(t *testing.T) {
	list := `# comment
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com www.tracker.example.com
:: ipv6ads.example.com
0.0.0.0 localhost
`
	res := ParseList(strings.NewReader(list))
	for _, d := range []string{"ads.example.com", "tracker.example.com", "www.tracker.example.com", "ipv6ads.example.com"} {
		if _, ok := res.Blocks[d]; !ok {
			t.Errorf("missing block for %s", d)
		}
	}
	if _, ok := res.Blocks["localhost"]; ok {
		t.Error("localhost must never be blocked")
	}
}

func TestParseAdblockFormat(t *testing.T) {
	list := `! title: test
||ads.example.com^
||banners.example.com^$third-party
@@||ok.ads.example.com^
example.com##.ad-banner
|https://malware.example.com/bad.js|
`
	res := ParseList(strings.NewReader(list))
	if _, ok := res.Blocks["ads.example.com"]; !ok {
		t.Error("missing ||ads.example.com^")
	}
	if _, ok := res.Blocks["banners.example.com"]; !ok {
		t.Error("missing banners.example.com")
	}
	if _, ok := res.Allows["ok.ads.example.com"]; !ok {
		t.Error("missing @@ exception")
	}
	if _, ok := res.Blocks["example.com"]; ok {
		t.Error("cosmetic rule must not block domain")
	}
	if _, ok := res.Blocks["malware.example.com"]; ok {
		t.Error("URL pattern |https://| should not be imported as a domain")
	}
}

func TestParsePlainDomains(t *testing.T) {
	res := ParseList(strings.NewReader("ads.com\nbad.org # inline\nnot a domain\n"))
	if _, ok := res.Blocks["ads.com"]; !ok {
		t.Error("plain domain missing")
	}
	if _, ok := res.Blocks["bad.org"]; !ok {
		t.Error("inline comment handling failed")
	}
}

func TestParseGarbageDoesNotPanic(t *testing.T) {
	garbage := strings.Repeat("x", 3000) + "\n\x00\x01\x02\n" + strings.Repeat("a.com\n", 100)
	res := ParseList(strings.NewReader(garbage))
	if _, ok := res.Blocks["a.com"]; !ok {
		t.Error("expected a.com parsed")
	}
}
