// Package filter implements domain blocklist parsing, matching and refresh.
//
// The matcher is a memory-efficient two-level trie in the spirit of
// AdGuard's sbz-engine: domains are split into labels and indexed from the
// TLD side, so matching a query touches at most three small maps. An entry
// "example.com" blocks "example.com" and every subdomain of it.
package filter

import (
	"strings"

	"golang.org/x/net/idna"
)

var idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule())

// Normalize lowercases and converts a domain to its ASCII (punycode) form.
// Returns "" for names that cannot be represented.
func Normalize(domain string) string {
	d := strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if d == "" {
		return ""
	}
	if isASCII(d) {
		return d
	}
	ascii, err := idnaProfile.ToASCII(d)
	if err != nil {
		return ""
	}
	return ascii
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// sldNode holds entries for one second-level domain under a TLD.
type sldNode struct {
	blocked bool            // the SLD itself is blocked (covers whole subtree)
	subs    map[string]bool // blocked third-level labels (cover their subtrees)
}

// tldNode holds entries for one top-level domain.
type tldNode struct {
	blocked bool // the whole TLD is blocked
	slds    map[string]*sldNode
}

// DomainSet is a set of domain suffixes backed by a two-level trie.
type DomainSet struct {
	tlds map[string]*tldNode
	n    int
}

// NewDomainSet returns an empty set.
func NewDomainSet() *DomainSet {
	return &DomainSet{tlds: make(map[string]*tldNode)}
}

// Add inserts a domain; returns true when it was not present before.
func (s *DomainSet) Add(domain string) bool {
	d := Normalize(domain)
	if d == "" {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) == 1 {
		if !isTLDLike(labels[0]) {
			return false // bare hostnames cannot be suffix rules
		}
		n := s.tld(labels[0])
		if n.blocked {
			return false
		}
		n.blocked = true
		s.n++
		return true
	}
	tn := s.tld(labels[len(labels)-1])
	sn := s.sld(tn, labels[len(labels)-2])
	if len(labels) == 2 {
		if sn.blocked {
			return false
		}
		sn.blocked = true
		s.n++
		return true
	}
	// Three or more labels: the third-from-TLD label covers the whole
	// subtree below it, so deeper labels need no storage of their own.
	sub := labels[len(labels)-3]
	if sn.subs[sub] {
		return false
	}
	if sn.subs == nil {
		sn.subs = make(map[string]bool)
	}
	sn.subs[sub] = true
	s.n++
	return true
}

// Has reports whether domain matches any stored suffix.
func (s *DomainSet) Has(domain string) bool {
	d := Normalize(domain)
	if d == "" {
		return false
	}
	labels := strings.Split(d, ".")
	tn, ok := s.tlds[labels[len(labels)-1]]
	if !ok {
		return false
	}
	if tn.blocked {
		return true
	}
	if len(labels) == 1 {
		return false
	}
	sn, ok := tn.slds[labels[len(labels)-2]]
	if !ok {
		return false
	}
	if sn.blocked {
		return true
	}
	if len(labels) >= 3 {
		return sn.subs[labels[len(labels)-3]]
	}
	return false
}

// Len returns the number of distinct entries added.
func (s *DomainSet) Len() int { return s.n }

// Each walks every stored rule and calls fn with the domain form that was
// added (TLD-only, SLD or third-level label). Order is not defined.
func (s *DomainSet) Each(fn func(domain string)) {
	for tld, tn := range s.tlds {
		if tn.blocked {
			fn(tld)
			continue
		}
		for sld, sn := range tn.slds {
			if sn.blocked {
				fn(sld + "." + tld)
				continue
			}
			for sub := range sn.subs {
				fn(sub + "." + sld + "." + tld)
			}
		}
	}
}

func (s *DomainSet) tld(name string) *tldNode {
	n, ok := s.tlds[name]
	if !ok {
		n = &tldNode{slds: make(map[string]*sldNode)}
		s.tlds[name] = n
	}
	return n
}

func (s *DomainSet) sld(t *tldNode, name string) *sldNode {
	n, ok := t.slds[name]
	if !ok {
		n = &sldNode{}
		t.slds[name] = n
	}
	return n
}

func isTLDLike(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
