# Supp

Self-hosted privacy DNS in a single static Go binary: **DoH + DoT + plain DNS** with network-wide ad, tracker and malware blocking. Point your devices at it — no apps, no clients. Works on phones, laptops, TVs and consoles, on Wi-Fi and mobile data alike.

```
device ──► DoH (443) / DoT (853) / DNS (53) ──► Supp ──► filtered + cached ──► upstream
admin  ──► token-gated dashboard ──► stats · devices · live queries
```

## Why

- **One binary, every device** — Android Private DNS, iOS/macOS DoH profiles, Windows 11 DoH, browsers, and plain-DNS gadgets all speak to the same server.
- **Fast and small** — pure-Go, `CGO_ENABLED=0` static build (~17 MB), LRU reply cache with serve-stale, upstream health tracking and weighted failover. RSS stays around 50–70 MB with a 100k-domain blocklist.
- **Blocks before it resolves** — blocked names never reach an upstream; CNAME-cloaked trackers are re-checked across the answer chain.
- **Private by default** — query logging off, only rolling counters kept. No telemetry, no external calls beyond your chosen upstreams and blocklists.
- **Per-device identities** — each device gets a secret DoH URL (`https://your-domain/dns/<token>`) for per-device stats and instant revocation.
- **Built-in WireGuard VPN** — hide device IPs and cover networks where encrypted DNS is blocked (hotel/office firewalls, carriers forcing their own resolvers). One binary manages the interface, peers and NAT; phone setup is a QR scan.

## Install (VPS)

Requirements: a VPS with ports 53/853/443 free, and (for automatic HTTPS) a DNS A/AAAA record pointing at it.

```sh
curl -fsSL https://raw.githubusercontent.com/0xsaurabhx/Supp/main/install.sh | sudo sh
```

or grab a prebuilt binary from [Releases](https://github.com/0xsaurabhx/Supp/releases) and install manually:

```sh
make release                       # builds supp-linux-amd64 / -arm64
sudo install -m755 supp-linux-amd64 /usr/local/bin/supp
sudo mkdir -p /etc/supp /var/lib/supp
sudo supp init --config /etc/supp/config.toml --domain dns.example.com
sudo cp scripts/supp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now supp
```

Without a domain, Supp runs in **local mode**: self-signed TLS, plain DNS and token DoH still work (`curl -k` / skip-verify clients).

> [!NOTE]
> If port 53 is already in use by `systemd-resolved` (common on Ubuntu/Debian), stop and disable it or set `DNSStubListener=no` in `/etc/systemd/resolved.conf`:
> ```sh
> sudo systemctl stop systemd-resolved
> sudo systemctl disable systemd-resolved
> ```

## Configure your devices

| Device | Where | Value |
|---|---|---|
| Android 9+ | Settings → Network → Private DNS | `dns.example.com` |
| iOS / macOS | DoH configuration profile | `https://dns.example.com/dns-query` |
| Windows 11 | Settings → Network → DNS → Manual | `dns.example.com` (DoH) |
| Any browser | Secure DNS → custom | `https://dns.example.com/dns-query` |
| TV / console / IoT | DNS server setting | your VPS IP (port 53) |

Per-device URL (stats + revocation): `supp client add pixel` → use `https://dns.example.com/dns/<token>` as the device's DoH URL.

## CLI

```
supp init      [--config PATH] [--domain NAME] [--token TOK]
supp server    [--config PATH]
supp client    add <name> | list | revoke <name>   [--config PATH]
supp wg        enable | disable | add <name> [--split] | list | qr <name> | remove <name> | show
supp status    [--config PATH]
supp doctor    [--config PATH]
supp version
```

## WireGuard VPN (phase 2)

Encrypted DNS can be blocked or ignored by hostile networks — and DNS alone never hides your IP. The optional WireGuard module solves both: devices tunnel through your VPS, and their DNS queries land in Supp, so ad/tracker blocking keeps working inside the tunnel.

Enable on the server (Linux, root — kernel WireGuard + iproute2 required):

```sh
sudo supp wg enable        # creates supp0, sets ip_forward + NAT, listens on :51820/udp
supp wg add laptop         # prints a ready-to-use .conf
supp wg qr laptop          # terminal QR — scan with the WireGuard app
supp wg list               # name, tunnel IP, rx/tx, last handshake
sudo supp wg disable       # removes interface + NAT rules (peers kept)
```

Or manage everything from the dashboard's **VPN** tab: add peers, show the QR, revoke or delete devices. Peers are full-tunnel by default (`0.0.0.0/0, ::/0` — IP hidden); add `--split` to route only DNS plus configured `split_networks`. Revoking a peer pulls it from the kernel instantly while keeping its row and stats.

```toml
[wg]
enabled = true
interface = "supp0"
port = 51820
subnet = "10.66.0.0/24"    # server takes .1
endpoint = ""              # defaults to server.domain:port
default_full_tunnel = true
split_networks = []        # extra CIDRs routed in split mode
```

> [!NOTE]
> If you run supp under systemd, uncomment the `AmbientCapabilities` lines in `scripts/supp.service` when `wg.enabled = true` — the module needs `CAP_NET_ADMIN` to create the interface and NAT rules.

## Blocklists

HaGeZi Normal is the default. Add or swap lists in `config.toml`:

```toml
[[block.lists]]
name = "oisd"
url = "https://big.oisd.nl/domainswild"
format = "domains"          # hosts | domains | adguard | auto
```

Lists refresh daily with ETag/If-Modified-Since; a failed refresh falls back to the cached copy so protection never silently widens. Inline `allowlist` / `denylist` entries always win.

## Upstreams

Defaults are Quad9 + Cloudflare DoH with a plain-DNS fallback. Schemes: `doh://` `dot://` `udp://` `tcp://`. Supp health-checks upstreams, prefers the fastest (EMA latency × in-flight), and fails over per query. If every upstream fails, a browser-fingerprint (uTLS) DoH fallback is used — kept cold otherwise.

```toml
[[dns.upstreams]]
url = "doh://dns.quad9.net/dns-query"
weight = 3
```

## Dashboard

Token-gated (`admin.token`), htmx-embedded, no external JS. Live counters, per-device queries/blocked, recent-queries ring (memory only, 200 entries), blocklist source status. When `log.queries = true`, top blocked domains are also collected (stored 30 days by default).


Releases are built automatically for linux/amd64 and linux/arm64 on every `v*` tag (see `.github/workflows/release.yml`).

## Development

```sh
make build    # static binary
make test     # go test ./...
make race     # -race
make vet      # go vet
make bench    # filter + cache benchmarks
```

Layout: `cmd/supp` (CLI) · `internal/dns` (listeners, cache, pool) · `internal/filter` (lists, matcher, engine) · `internal/admin` (dashboard) · `internal/store` (SQLite counters) · `internal/wg` (WireGuard VPN) · `internal/ops` (init, TLS/autocert).

## Honest limits

- Same-domain ads (YouTube etc.) can't be fully blocked at DNS level.
- Apps hardcoding their own DoH bypass local settings unless your router forces port 53 to Supp.
- The VPN module manages **kernel** WireGuard on Linux (any VPS); config/QR generation also works on other platforms, but the interface itself is Linux-only. Userspace fallback is a possible phase 3.
