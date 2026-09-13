package admin

import (
	"strings"
	"testing"

	"github.com/0xsaurabhx/Supp/internal/store"
	"github.com/0xsaurabhx/Supp/internal/wg"
)

// TestTemplatesParse exercises the package-level template (its init would
// panic on malformed templates) and renders the VPN view both enabled and
// disabled to catch template/runtime mismatches.
func TestTemplatesParse(t *testing.T) {
	if tpl == nil {
		t.Fatal("templates not parsed")
	}

	// WG disabled: the "module not running" branch.
	var b strings.Builder
	err := tpl.ExecuteTemplate(&b, "layout.html", pageData{View: "wg", Token: "tok", Stats: &statsView{}})
	if err != nil {
		t.Fatalf("render wg (disabled): %v", err)
	}
	if !strings.Contains(b.String(), "supp wg enable") {
		t.Error("disabled view should show the enable hint")
	}

	// WG enabled: peer table renders.
	b.Reset()
	st := wg.Status{
		Interface: "supp0", Endpoint: "vpn.example.com:51820",
		Subnet: "10.66.0.0/24", ServerIP: "10.66.0.1", Up: true,
		Peers: []store.WgPeer{},
	}
	err = tpl.ExecuteTemplate(&b, "layout.html", pageData{View: "wg", Token: "tok", Stats: &statsView{}, WG: &st})
	if err != nil {
		t.Fatalf("render wg (enabled, no peers): %v", err)
	}
	if !strings.Contains(b.String(), "vpn.example.com:51820") {
		t.Error("enabled view should show the endpoint")
	}
}
