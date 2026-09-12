package filter

import (
	"bufio"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// List formats.
const (
	FormatHosts   = "hosts"
	FormatDomains = "domains"
	FormatAdguard = "adguard"
	FormatAuto    = "auto"
)

// ParsedList holds entries extracted from one blocklist source.
type ParsedList struct {
	Format  string
	Blocked []string // exact/suffix domains to block
	Allowed []string // @@ entries from AdGuard-syntax lists
}

var reAdguard = regexp.MustCompile(`^\|\|([a-z0-9*._-]+)\^(\$([^,]*))?$`)

// Parse parses a list in the given format ("auto" sniffs the format).
func Parse(r io.Reader, format string) (*ParsedList, error) {
	switch format {
	case FormatHosts:
		return parseHosts(r)
	case FormatDomains:
		return parseDomains(r)
	case FormatAdguard:
		return parseAdguard(r)
	case FormatAuto, "":
		return ParseAuto(r)
	default:
		return nil, errors.New("unknown list format: " + format)
	}
}

// ParseAuto sniffs the list format from its first meaningful lines and
// parses the whole stream accordingly.
func ParseAuto(r io.Reader) (*ParsedList, error) {
	br := bufio.NewReader(io.LimitReader(r, 8<<10))
	var first []string
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			t := strings.TrimSpace(line)
			if t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "!") && !strings.HasPrefix(t, "[") {
				first = append(first, t)
				if len(first) >= 8 {
					break
				}
			}
		}
		if err != nil {
			break
		}
	}
	if len(first) == 0 {
		return parseDomains(io.MultiReader(strings.NewReader(""), r))
	}
	for _, t := range first {
		f := strings.Fields(t)
		if len(f) >= 2 && (isIP(f[0])) {
			return parseHosts(r)
		}
	}
	for _, t := range first {
		if strings.HasPrefix(t, "||") {
			return parseAdguard(r)
		}
	}
	return parseDomains(r)
}

func parseHosts(r io.Reader) (*ParsedList, error) {
	pl := &ParsedList{Format: FormatHosts}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 || !isIP(f[0]) {
			continue
		}
		for _, d := range f[1:] {
			if d != "" && d != "localhost" && !strings.HasPrefix(d, "ip6-") {
				pl.Blocked = append(pl.Blocked, d)
			}
		}
	}
	return pl, sc.Err()
}

func parseDomains(r io.Reader) (*ParsedList, error) {
	pl := &ParsedList{Format: FormatDomains}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		pl.Blocked = append(pl.Blocked, line)
	}
	return pl, sc.Err()
}

func parseAdguard(r io.Reader) (*ParsedList, error) {
	pl := &ParsedList{Format: FormatAdguard}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		if m := reAdguard.FindStringSubmatch(line); m != nil {
			dom := strings.TrimPrefix(m[1], "*.")
			dom = strings.Trim(dom, "*.")
			if dom == "" {
				continue
			}
			if strings.Contains(line, "$important") || strings.Contains(m[3], "important") {
				// treat as block even if also allowlisted; simple policy
				pl.Blocked = append(pl.Blocked, dom)
				continue
			}
			pl.Blocked = append(pl.Blocked, dom)
		} else if strings.HasPrefix(line, "@@||") {
			if m := reAdguard.FindStringSubmatch(strings.TrimPrefix(line, "@@")); m != nil {
				dom := strings.Trim(strings.TrimPrefix(m[1], "*."), "*.")
				if dom != "" {
					pl.Allowed = append(pl.Allowed, dom)
				}
			}
		}
	}
	return pl, sc.Err()
}

func isIP(s string) bool {
	// Avoid pulling net just for this: quick check for IPv4/IPv6-ish tokens.
	if strings.Contains(s, ":") {
		return true // IPv6 literal orSomething; hosts lists only carry literals
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

// LoadList reads a list from a local file path.
func LoadList(path string) (*ParsedList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseAuto(f)
}

// ValidURL reports whether s looks like an http(s) URL.
func ValidURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}
