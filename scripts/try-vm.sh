#!/usr/bin/env bash
# Turn a fresh Linux VM into a portash test VM behind a Cloudflare quick
# tunnel: no Cloudflare account, domain or open port needed. For trying
# portash out only; use a named tunnel (README) for real VMs.
#
#   on the laptop:  portash device                       # prints pshd_...
#   copy portash (Linux build) and this script to the VM, then on the VM:
#                   sudo ./try-vm.sh ./portash pshd_...
#   to undo:        sudo ./try-vm.sh --remove
#
# sshd is left as it is, so your usual way in keeps working while you test.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }

if [ "${1:-}" = --remove ]; then
  systemctl disable --now portash-gateway portash-quicktunnel 2>/dev/null || true
  rm -f /etc/systemd/system/portash-gateway.service /etc/systemd/system/portash-quicktunnel.service
  systemctl daemon-reload
  rm -rf /var/lib/portash /usr/local/bin/portash /usr/local/bin/cloudflared
  userdel portash 2>/dev/null || true
  echo "removed portash, the quick tunnel and their state"
  exit 0
fi

BIN=${1:?usage: try-vm.sh PATH-TO-PORTASH pshd_DEVICE-KEY}
DEVICE=${2:?usage: try-vm.sh PATH-TO-PORTASH pshd_DEVICE-KEY}
case "$DEVICE" in pshd_*) ;; *) echo "the second argument is the pshd_... key from 'portash device'"; exit 1 ;; esac

install -m 755 "$BIN" /usr/local/bin/portash
id portash >/dev/null 2>&1 || useradd --system --home-dir /var/lib/portash --shell /usr/sbin/nologin portash
install -d -o portash -g portash -m 700 /var/lib/portash
ERR=$(mktemp); trap 'rm -f "$ERR"' EXIT

# cloudflared, pinned to one release and checked against its SHA-256 (taken
# from the GitHub release download when this script was written).
CFD_VERSION=2026.10.0
case "$(uname -m)" in
  x86_64) ARCH=amd64; CFD_SHA=d33ff2d14475178d2012c2c56beba87389ac5ded27649519f198a7d3134a99db ;;
  aarch64|arm64) ARCH=arm64; CFD_SHA=e6422b9d4f72d3194bc5a38676f13667c06666523217b842a877d72a80b5ac08 ;;
  *) echo "unsupported CPU $(uname -m)"; exit 1 ;;
esac
if ! command -v cloudflared >/dev/null; then
  echo "downloading cloudflared $CFD_VERSION..."
  TMP=$(mktemp)
  curl -fsSL -o "$TMP" \
    "https://github.com/cloudflare/cloudflared/releases/download/$CFD_VERSION/cloudflared-linux-$ARCH"
  echo "$CFD_SHA  $TMP" | sha256sum -c --quiet - || { echo "cloudflared checksum mismatch"; rm -f "$TMP"; exit 1; }
  install -m 755 "$TMP" /usr/local/bin/cloudflared
  rm -f "$TMP"
fi

# A token for this laptop, and a TOTP secret for the daily unlock.
portash token rm tester --dir /var/lib/portash >/dev/null 2>&1 || true
TOKEN=$(portash token add tester --device "$DEVICE" --ttl 168h --dir /var/lib/portash 2>"$ERR") || { cat "$ERR"; exit 1; }
portash totp rm tester --unlock --dir /var/lib/portash >/dev/null 2>&1 || true
URI=$(portash totp enroll tester --unlock --dir /var/lib/portash 2>"$ERR") || { cat "$ERR"; exit 1; }
PIN=$(portash fingerprint --dir /var/lib/portash)

cat >/etc/systemd/system/portash-gateway.service <<'UNIT'
[Unit]
Description=portash gateway (test, behind a Cloudflare quick tunnel)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/portash gateway --network 127.0.0.1/32 --ports 22 --dir /var/lib/portash --require-unlock \
    --listen "" --tunnel-listen 127.0.0.1:8080 --tunnel-ip-header CF-Connecting-IP
Restart=on-failure
User=portash
Group=portash
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/portash
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/portash-quicktunnel.service <<'UNIT'
[Unit]
Description=Cloudflare quick tunnel to the portash gateway (test only)
After=network-online.target portash-gateway.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/cloudflared tunnel --no-autoupdate --url http://127.0.0.1:8080
Restart=on-failure
DynamicUser=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now portash-gateway >/dev/null 2>&1
systemctl restart portash-gateway
SINCE=$(date '+%Y-%m-%d %H:%M:%S')
systemctl enable portash-quicktunnel >/dev/null 2>&1
systemctl restart portash-quicktunnel

echo "waiting for the tunnel URL..."
URL=""
for _ in $(seq 60); do
  URL=$(journalctl -u portash-quicktunnel --since "$SINCE" --no-pager 2>/dev/null |
    grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | grep -v '//api\.' | head -1 || true) # api. is not a tunnel
  [ -n "$URL" ] && break
  sleep 1
done
[ -n "$URL" ] || { echo "no tunnel URL; see: journalctl -u portash-quicktunnel"; exit 1; }
LOGIN=$(logname 2>/dev/null || echo "${SUDO_USER:-root}")

cat <<EOF

portash test VM is ready at $URL
(the URL changes if the VM or the tunnel restarts: run this script again)

1. Add this to your authenticator app (or scan: qrencode -t ansiutf8 '<the link>'):
   $URI

2. On your laptop:
   portash login trytest --gateway $URL --pin $PIN
   (paste this token when asked: $TOKEN)
   portash ssh-config trytest >> ~/.ssh/config
   (Windows PowerShell: portash ssh-config trytest | Out-File -Append -Encoding ascii \$HOME\.ssh\config)

3. Every day, then ssh:
   portash unlock
   ssh -o StrictHostKeyChecking=accept-new $LOGIN@trytest
   (accept-new only the first time: this test skips the host certificate
   step, so ssh has no CA to check the VM's host key against)
Remove everything with: sudo $0 --remove
EOF
