package filter

import (
	"strings"
	"testing"
)

func TestDomainSetSuffixMatching(t *testing.T) {
	s := NewDomainSet()
	s.Add("doubleclick.net")
	s.Add("ads.google.com")
	s.Add("example.org")

	cases := []struct {
		q    string
		want bool
	}{
		{"doubleclick.net", true},
		{"www.doubleclick.net", true},
		{"a.b.c.doubleclick.net", true},
		{"notdoubleclick.net", false},
		{"doubleclick.net.evil.com", false},
		{"ads.google.com", true},
		{"analytics.ads.google.com", true},
		{"google.com", false}, // SLD not blocked, only sub
		{"ads.ggoogle.com", false},
		{"example.org", true},
		{"www.example.org", true},
		{"example.org.evil.com", false},
		{"EXAMPLE.ORG", true},  // case-insensitive
		{"example.org.", true}, // trailing dot
	}
	for _, c := range cases {
		if got := s.Has(c.q); got != c.want {
			t.Errorf("Has(%q) = %v, want %v", c.q, got, c.want)
		}
	}
	if s.Len() != 3 {
		t.Errorf("Len = %d, want 3", s.Len())
	}
}

func TestDomainSetBlockedTLD(t *testing.T) {
	s := NewDomainSet()
	s.Add("example")
	cases := map[string]bool{"example": true, "foo.example": true, "other": false}
	for q, want := range cases {
		if got := s.Has(q); got != want {
			t.Errorf("Has(%q) = %v, want %v", q, got, want)
		}
	}
}

func TestDomainSetDedup(t *testing.T) {
	s := NewDomainSet()
	if !s.Add("ads.example.com") {
		t.Fatal("first add should be new")
	}
	if s.Add("ads.example.com") {
		t.Fatal("second add should be dedup")
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1", s.Len())
	}
}

func TestNormalizeIDN(t *testing.T) {
	if got := Normalize("BÜCHER.Example.COM"); got != "xn--bcher-kva.example.com" {
		t.Errorf("IDN normalize = %q", got)
	}
	if got := Normalize(".example.com."); got != "example.com" {
		t.Errorf("trim dots = %q", got)
	}
}

func TestParseHosts(t *testing.T) {
	in := `# comment
127.0.0.1 localhost
0.0.0.0 ads.example.com www.tracker.net # inline comment
::1 ip6-localhost
0.0.0.0 another.ads.io`
	pl, err := Parse(strings.NewReader(in), FormatHosts)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ads.example.com", "www.tracker.net", "another.ads.io"}
	if len(pl.Blocked) != len(want) {
		t.Fatalf("got %v, want %v", pl.Blocked, want)
	}
	for i, d := range want {
		if pl.Blocked[i] != d {
			t.Errorf("entry %d = %q, want %q", i, pl.Blocked[i], d)
		}
	}
}

func TestParseDomains(t *testing.T) {
	in := `# list title
ads.example.com
tracker.net   # trailing comment

! another comment
`
	pl, err := Parse(strings.NewReader(in), FormatDomains)
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Blocked) != 2 || pl.Blocked[0] != "ads.example.com" || pl.Blocked[1] != "tracker.net" {
		t.Fatalf("got %v", pl.Blocked)
	}
}

func TestParseAdguard(t *testing.T) {
	in := `! Title
||ads.example.com^
||tracker.net^$important
@@||good.example.com^
||sub.wildcard.org^$third-party
`
	pl, err := Parse(strings.NewReader(in), FormatAdguard)
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Blocked) != 3 {
		t.Fatalf("blocked = %v", pl.Blocked)
	}
	if len(pl.Allowed) != 1 || pl.Allowed[0] != "good.example.com" {
		t.Fatalf("allowed = %v", pl.Allowed)
	}
}

func TestParseAutoDetect(t *testing.T) {
	hosts := "0.0.0.0 ads.example.com\n"
	if pl, err := Parse(strings.NewReader(hosts), FormatAuto); err != nil || pl.Format != FormatHosts {
		t.Fatalf("hosts sniff: %v %v", pl, err)
	}
	domains := "# t\nads.example.com\ntracker.net\n"
	if pl, err := Parse(strings.NewReader(domains), FormatAuto); err != nil || pl.Format != FormatDomains {
		t.Fatalf("domains sniff: %v %v", pl, err)
	}
	ag := "||ads.example.com^\n"
	if pl, err := Parse(strings.NewReader(ag), FormatAuto); err != nil || pl.Format != FormatAdguard {
		t.Fatalf("adguard sniff: %v %v", pl, err)
	}
}

func TestEngineAllowWins(t *testing.T) {
	e := NewEngine(t.TempDir(), nil, []string{"keep.example.com"}, []string{"example.com"}, 0)
	if e.Check("keep.example.com") {
		t.Error("allowlist must win over denylist")
	}
	if e.Check("sub.keep.example.com") {
		t.Error("allowlist covers subdomains")
	}
	if !e.Check("other.example.com") {
		t.Error("denylist should block")
	}
}

func BenchmarkHas(b *testing.B) {
	s := NewDomainSet()
	for i := 0; i < 100000; i++ {
		s.Add("d" + strings.Repeat("x", 3) + itoa(i) + ".example" + itoa(i%97) + ".com")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Has("www.miss-domain-just-browsing.net")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
