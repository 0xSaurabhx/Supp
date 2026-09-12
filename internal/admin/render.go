package admin

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html static/*
var templateFS embed.FS

var tpl = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// pageData is the model passed to every page.
type pageData struct {
	View  string
	Stats *statsView
	Token string
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
<html lang="en"><head><meta charset="utf-8"><title>Supp — sign in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;background:#0b0f14;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0}
.card{background:#11161d;padding:2rem;border-radius:12px;width:min(92vw,360px)}
input{width:100%;padding:.6rem;margin:.4rem 0;border-radius:8px;border:1px solid #2d333b;background:#0b0f14;color:#e6edf3}
button{width:100%;padding:.6rem;border-radius:8px;border:0;background:#2f81f7;color:#fff;font-weight:600}
</style></head><body><div class="card"><h2>Supp</h2><p>Enter the admin token from <code>/etc/supp/config.toml</code>.</p>
<form onsubmit="document.cookie='supp_admin='+encodeURIComponent(this.t.value)+';path=/;max-age=43200';location.reload();return false">
<input name="t" type="password" placeholder="admin token" autofocus><button>Sign in</button></form></div></body></html>`
