#!/usr/bin/env bash
# Start sshd, the portash gateway and (by default) a Cloudflare quick tunnel,
# then print the laptop steps. Everything is created fresh on each start.
#
#   DEVICE   the pshd_... key from 'portash device' on the laptop (required)
#   SSH_KEY  the laptop's ssh public key, e.g. contents of ~/.ssh/id_ed25519.pub
#   MODE     tunnel (default) or direct (gateway on port 443, publish it with -p)
set -euo pipefail

: "${DEVICE:?set -e DEVICE=pshd_... (run 'portash device' on the laptop)}"
: "${SSH_KEY:?set -e SSH_KEY=\"\$(cat ~/.ssh/id_ed25519.pub)\"}"
MODE=${MODE:-tunnel}
case "$DEVICE" in pshd_*) ;; *) echo "DEVICE must be the pshd_... key from 'portash device'"; exit 1 ;; esac
case "$MODE" in tunnel|direct) ;; *) echo "MODE must be tunnel or direct"; exit 1 ;; esac

# sshd on localhost only, keys only, for one user.
id tester >/dev/null 2>&1 || useradd -m -s /bin/bash tester
install -d -m 700 -o tester -g tester /home/tester/.ssh
printf '%s\n' "$SSH_KEY" >/home/tester/.ssh/authorized_keys
chown tester:tester /home/tester/.ssh/authorized_keys
chmod 600 /home/tester/.ssh/authorized_keys
ssh-keygen -A >/dev/null
mkdir -p /run/sshd
cat >/etc/ssh/sshd_config.d/portash.conf <<'CONF'
ListenAddress 127.0.0.1
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers tester
CONF
/usr/sbin/sshd

# A token for this laptop, and a TOTP secret for the daily unlock.
DIR=/var/lib/portash
install -d -m 700 "$DIR"
TOKEN=$(portash token add tester --device "$DEVICE" --ttl 168h --dir "$DIR" 2>/tmp/portash.err) || { cat /tmp/portash.err; exit 1; }
URI=$(portash totp enroll tester --unlock --dir "$DIR" 2>/tmp/portash.err) || { cat /tmp/portash.err; exit 1; }
PIN=$(portash fingerprint --dir "$DIR")

if [ "$MODE" = direct ]; then
  portash gateway --network 127.0.0.1/32 --ports 22 --dir "$DIR" --require-unlock --listen :443 &
  GATEWAY="localhost:8443"
  NOTE="(assumes you started the container with -p 8443:443; use HOST:8443 from another machine)"
else
  portash gateway --network 127.0.0.1/32 --ports 22 --dir "$DIR" --require-unlock \
    --listen "" --tunnel-listen 127.0.0.1:8080 --tunnel-ip-header CF-Connecting-IP &
  cloudflared tunnel --no-autoupdate --url http://127.0.0.1:8080 >/tmp/cloudflared.log 2>&1 &
  CFD=$!
  echo "waiting for the tunnel URL..."
  GATEWAY=""
  for _ in $(seq 60); do
    # api.trycloudflare.com is where cloudflared asks for a tunnel, not one.
    GATEWAY=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' /tmp/cloudflared.log | grep -v '//api\.' | head -1 || true)
    [ -n "$GATEWAY" ] && break
    kill -0 "$CFD" 2>/dev/null || break
    sleep 1
  done
  [ -n "$GATEWAY" ] || { echo "no tunnel URL; cloudflared said:"; cat /tmp/cloudflared.log; exit 1; }
  NOTE="(a new URL on every start: log in again after restarting the container)"
fi

cat <<EOF

portash test container is ready at $GATEWAY
$NOTE

1. Add this to your authenticator app:
   $URI

2. On your laptop:
   portash login trytest --gateway $GATEWAY --pin $PIN
   (paste this token when asked: $TOKEN)
   portash ssh-config trytest >> ~/.ssh/config
   (Windows PowerShell: portash ssh-config trytest | Out-File -Append -Encoding ascii \$HOME\.ssh\config)
   Then under "Host trytest" in ~/.ssh/config add:   User tester

3. Then:
   portash unlock
   ssh trytest

ssh asks you to accept the host key the first time. Stop with Ctrl-C.
EOF

# Stop the container when any of the services stops.
wait -n
echo "a service stopped; exiting"
exit 1
