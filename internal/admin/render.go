package admin

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"

	"github.com/0xsaurabhx/Supp/internal/wg"
)

//go:embed templates/*.html static/*
var templateFS embed.FS

var tpl = template.Must(template.New("layout.html").Funcs(template.FuncMap{
	"add1":       func(i int) int { return i + 1 },
	"humanBytes": humanBytes,
}).ParseFS(templateFS, "templates/*.html"))

// humanBytes renders a byte count for the dashboard (12.3M).
func humanBytes(n uint64) string {
	const k = 1024
	switch {
	case n >= k*k*k*k:
		return fmt.Sprintf("%.1fT", float64(n)/(k*k*k*k))
	case n >= k*k*k:
		return fmt.Sprintf("%.1fG", float64(n)/(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.1fM", float64(n)/(k*k))
	case n >= k:
		return fmt.Sprintf("%.1fK", float64(n)/k)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// pageData is the model passed to every page.
type pageData struct {
	View  string
	Stats *statsView
	Token string
	WG    *wg.Status // nil when the VPN module is disabled
}

// render writes a page; layout.html defines the shell and imports the view.
func render(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := tpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, "template error: "+err.Error(), 500)
	}
}

// loginPageHTML is shown when the token is missing or wrong.
const loginPageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Supp — Admin Sign In</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root { --bg: #090d16; --card: #111827; --border: rgba(255,255,255,0.08); --primary: #6366f1; --primary-hover: #4f46e5; --text: #f8fafc; --muted: #94a3b8; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Plus Jakarta Sans', system-ui, sans-serif; background: var(--bg); color: var(--text); display: grid; place-items: center; min-height: 100vh; overflow: hidden; position: relative; }
body::before { content: ''; position: absolute; width: 500px; height: 500px; background: radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, rgba(99, 102, 241, 0) 70%); top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 0; pointer-events: none; }
.login-card { background: rgba(17, 24, 39, 0.8); backdrop-filter: blur(16px); border: 1px solid var(--border); padding: 2.5rem 2.2rem; border-radius: 24px; width: min(92vw, 400px); z-index: 1; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); text-align: center; }
.logo-icon { width: 54px; height: 54px; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); border-radius: 16px; display: inline-flex; align-items: center; justify-content: center; font-size: 1.7rem; color: #fff; margin-bottom: 1.2rem; box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.5); }
h2 { font-size: 1.6rem; font-weight: 800; tracking: -0.02em; margin-bottom: 0.4rem; background: linear-gradient(to right, #ffffff, #cbd5e1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
p { font-size: 0.9rem; color: var(--muted); margin-bottom: 1.8rem; line-height: 1.5; }
code { font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 6px; color: #e2e8f0; }
input { width: 100%; padding: 0.85rem 1rem; border-radius: 12px; border: 1px solid var(--border); background: rgba(10, 14, 23, 0.7); color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; margin-bottom: 1rem; transition: all 0.2s; }
input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.2); }
button { width: 100%; padding: 0.85rem; border-radius: 12px; border: 0; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: #fff; font-family: 'Plus Jakarta Sans', sans-serif; font-weight: 700; font-size: 0.95rem; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4); }
button:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(99, 102, 241, 0.6); }
button:active { transform: translateY(0); }
</style></head><body>
<div class="login-card">
  <div class="logo-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
  <h2>Supp Privacy DNS</h2>
  <p>Enter the admin token configured in <code>/etc/supp/config.toml</code> to access your dashboard.</p>
  <form onsubmit="document.cookie='supp_admin='+encodeURIComponent(this.t.value)+';path=/;max-age=43200';location.reload();return false">
    <input name="t" type="password" placeholder="••••••••••••••••" autofocus required>
    <button type="submit">Unlock Dashboard</button>
  </form>
</div>
</body></html>`
