#!/bin/sh
# Supp installer: downloads the right binary for this machine and installs
# the systemd service. Run on the VPS:  curl -fsSL <url>/install.sh | sh
set -eu

REPO_URL="${SUPP_DOWNLOAD_URL:-https://github.com/0xsaurabhx/Supp/releases/latest/download}"
INSTALL_BIN=/usr/local/bin/supp
CONFIG_DIR=/etc/supp
DATA_DIR=/var/lib/supp

echo "==> Supp installer"

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: install.sh must be run as root. Please run: curl -fsSL ... | sudo sh" >&2
  exit 1
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl kill -s SIGKILL supp 2>/dev/null || true
  systemctl stop --no-block supp 2>/dev/null || true
fi

# 2. Download binary
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) SUPP_ARCH=amd64 ;;
  aarch64|arm64) SUPP_ARCH=arm64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "==> downloading supp-linux-$SUPP_ARCH"
curl -fsSL "$REPO_URL/supp-linux-$SUPP_ARCH" -o "$TMP/supp"
chmod 0755 "$TMP/supp"
install -m 0755 "$TMP/supp" "$INSTALL_BIN"

# 3. Dirs and config
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
  echo "==> creating default config (edit $CONFIG_DIR/config.toml, then re-run init)"
  $INSTALL_BIN init --config "$CONFIG_DIR/config.toml" --token "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
else
  echo "==> config exists, keeping it"
fi

# 4. systemd
if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/supp.service <<'EOF'
[Unit]
Description=Supp privacy DNS server (DoH/DoT/plain + blocking)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/supp server --config /etc/supp/config.toml
Restart=on-failure
RestartSec=3
TimeoutStopSec=10s
User=root
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/supp
ProtectHome=yes
PrivateTmp=yes
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now supp
  echo "==> service started: systemctl status supp"
fi

echo "==> done. Next:"
echo "    1. Point a DNS A record at this server (if you want DoH/DoT)."
echo "    2. Edit /etc/supp/config.toml (set server.domain)."
echo "    3. sudo supp init"
echo "    4. systemctl restart supp"
