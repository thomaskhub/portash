#!/usr/bin/env bash
# Real OpenSSH through portash on one machine. 127.0.0.2 stands in for a VM's
# VPN address and 127.0.0.0/8 for the VPN network. --direct-timeout 0
# simulates a hotel that blocks UDP (VPN down, only the gateway path works).
# Needs: go, openssh-server, openssh-client. Run as root (sshd needs it).
set -euo pipefail
cd "$(dirname "$0")/.."
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
go build -o "$T/portash" ./cmd/portash
export HOME="$T/home" XDG_CONFIG_HOME="$T/home/.config"; mkdir -p "$HOME"

# Host CA: the VM's host key is signed, the laptop trusts only the CA.
ssh-keygen -q -t ed25519 -N '' -f "$T/host_ca"
ssh-keygen -q -t ed25519 -N '' -f "$T/hostkey"
ssh-keygen -q -s "$T/host_ca" -I vm -h -n 127.0.0.2,vm2 -V +1h "$T/hostkey.pub"
echo "@cert-authority 127.0.0.2,vm2 $(cat "$T/host_ca.pub")" >"$T/known_hosts"

# Users: full key, restricted key, and a forced-command key missing "restrict".
ssh-keygen -q -t ed25519 -N '' -f "$T/userkey"
ssh-keygen -q -t ed25519 -N '' -f "$T/cikey"
ssh-keygen -q -t ed25519 -N '' -f "$T/sloppykey"
printf 'uptime\necho ...\n' >"$T/policy"
{ cat "$T/userkey.pub"
  echo "restrict,command=\"$T/portash restrict --policy $T/policy --name ci\" $(cat "$T/cikey.pub")"
  echo "command=\"$T/portash restrict --policy $T/policy --name sloppy\" $(cat "$T/sloppykey.pub")"
} >"$T/authorized_keys"; chmod 600 "$T/authorized_keys"
mkdir -p /run/sshd
/usr/sbin/sshd -D -e -f /dev/null -o ListenAddress=127.0.0.2:2222 -o HostKey="$T/hostkey" \
  -o HostCertificate="$T/hostkey-cert.pub" -o AuthorizedKeysFile="$T/authorized_keys" \
  -o PasswordAuthentication=no -o StrictModes=no -o PidFile=none -o "Subsystem=sftp internal-sftp" 2>"$T/sshd.log" &

# Laptop makes a device key; the admin binds a token to it.
DEVICE=$("$T/portash" device 2>/dev/null)
"$T/portash" token add laptop --device "$DEVICE" --ttl 1h --dir "$T/gw" >"$T/token" 2>/dev/null
"$T/portash" gateway --dir "$T/gw" --listen 127.0.0.1:8443 --network 127.0.0.0/8 --ports 2222 2>"$T/gw.log" &
# The laptop reaches the gateway through a relay on 9443 that stands in for
# hotel Wi-Fi: killing it drops every connection, as a network change does.
cat >"$T/relay.py" <<'PY'
import socket, sys, threading
def pump(a, b):
    try:
        while (d := a.recv(65536)):
            b.sendall(d)
    except OSError:
        pass
    for s in (a, b):
        try: s.shutdown(socket.SHUT_RDWR)
        except OSError: pass
ln = socket.create_server(("127.0.0.1", 9443), reuse_port=True)
while True:
    c, _ = ln.accept()
    u = socket.create_connection(("127.0.0.1", 8443))
    threading.Thread(target=pump, args=(c, u), daemon=True).start()
    threading.Thread(target=pump, args=(u, c), daemon=True).start()
PY
python3 -I "$T/relay.py" & RELAY=$!
sleep 1
PIN=$("$T/portash" fingerprint --dir "$T/gw")
"$T/portash" login --gateway 127.0.0.1:9443 --pin "$PIN" --network 127.0.0.0/8 <"$T/token"

SSHO=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile="$T/known_hosts"
      -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null)
GW="$T/portash dial -v --direct-timeout 0 %h %p"
SSH=(ssh "${SSHO[@]}" -i "$T/userkey" -p 2222)

echo "== via gateway (VPN down), host key verified by CA"
"${SSH[@]}" -o ProxyCommand="$GW" root@127.0.0.2 'echo hello via gateway'

echo "== scp 5 MB via gateway"
head -c 5000000 /dev/urandom >"$T/blob"
scp -q "${SSHO[@]}" -i "$T/userkey" -P 2222 -o ProxyCommand="$GW" "$T/blob" root@127.0.0.2:"$T/blob.copy"
cmp "$T/blob" "$T/blob.copy" && echo "scp ok, checksums match"

echo "== direct (route to 127.0.0.2 is inside the VPN network)"
"${SSH[@]}" -o ProxyCommand="$T/portash dial -v %h %p" root@127.0.0.2 'echo hello direct'

echo "== unknown host key is refused (no TOFU)"
if ssh -o UserKnownHostsFile=/dev/null "${SSHO[@]}" -i "$T/userkey" -p 2222 -o ProxyCommand="$GW" root@127.0.0.2 true 2>"$T/err"; then
  echo "FAIL: unverified host accepted"; exit 1; fi
grep -o 'Host key verification failed' "$T/err"

echo "== stolen token on another device is refused"
cp -r "$HOME/.config/portash" "$T/stolen"; rm "$T/stolen/device.key"
XDG_CONFIG_HOME="$T/thief" bash -c "mkdir -p $T/thief && cp -r $T/stolen $T/thief/portash && $T/portash device >/dev/null 2>&1"
if XDG_CONFIG_HOME="$T/thief" "${SSH[@]}" -o ProxyCommand="$GW" root@127.0.0.2 true 2>"$T/err"; then
  echo "FAIL: token worked from another device"; exit 1; fi
grep -o 'rejected.*' "$T/err" | head -1

echo "== restricted key"
CI=(ssh "${SSHO[@]}" -i "$T/cikey" -p 2222 -o ProxyCommand="$GW" root@127.0.0.2)
"${CI[@]}" uptime >/dev/null && echo "allowed: uptime"
out=$("${CI[@]}" 'echo hi; id')
[ "$out" = "hi; id" ] && echo "no shell: 'echo hi; id' printed literally: $out"
for denied in 'id' 'cat /etc/shadow' 'uptime --help' 'echo -e x'; do
  if "${CI[@]}" "$denied" 2>"$T/err"; then echo "FAIL: '$denied' was allowed"; exit 1; fi
  echo "denied: $denied ($(grep -m1 -v '^portash: via' "$T/err"))"
done
if "${CI[@]}" -T </dev/null 2>"$T/err"; then echo "FAIL: shell allowed"; exit 1; fi
echo "denied: interactive shell ($(grep -m1 -v '^portash: via' "$T/err"))"

echo "== key without the restrict option is refused"
if ssh "${SSHO[@]}" -tt -i "$T/sloppykey" -p 2222 -o ProxyCommand="$GW" root@127.0.0.2 uptime </dev/null >"$T/out" 2>&1; then
  echo "FAIL: key without restrict ran a command"; exit 1; fi
grep -o 'missing the "restrict" option' "$T/out"

echo "== session survives the network dropping for 3 seconds (no tmux)"
"${SSH[@]}" -o ProxyCommand="$GW" root@127.0.0.2 \
  'for i in 1 2 3 4 5 6 7 8 9 10; do echo tick$i; sleep 0.5; done' >"$T/ticks" 2>"$T/ticks.err" &
SP=$!; sleep 1.5
kill $RELAY; wait $RELAY 2>/dev/null || true   # Wi-Fi gone: every connection drops
sleep 3
python3 -I "$T/relay.py" & RELAY=$!             # back online
wait $SP || { echo "FAIL: ssh exited: $(cat "$T/ticks.err")"; exit 1; }
[ "$(tr '\n' ' ' <"$T/ticks")" = "tick1 tick2 tick3 tick4 tick5 tick6 tick7 tick8 tick9 tick10 " ] \
  || { echo "FAIL: output across the drop: $(cat "$T/ticks")"; exit 1; }
grep -o 'reconnected after.*' "$T/ticks.err"
echo "all 10 ticks arrived once, in order, and ssh never noticed"

echo "== open session is cut when the token is revoked"
"${SSH[@]}" -o ProxyCommand="$GW" root@127.0.0.2 'sleep 30' &
SESS=$!; sleep 2
"$T/portash" token rm laptop --dir "$T/gw"
for i in $(seq 1 20); do kill -0 $SESS 2>/dev/null || break; sleep 0.5; done
if kill -0 $SESS 2>/dev/null; then echo "FAIL: session survived revocation"; exit 1; fi
echo "session closed after revocation"
if "${SSH[@]}" -o ProxyCommand="$GW" root@127.0.0.2 true 2>"$T/err"; then
  echo "FAIL: revoked token still works"; exit 1; fi
grep -o 'rejected.*' "$T/err"

# Every other session must have ended when its ssh did (including the ones
# ssh aborted), not be left waiting for a resume until the token was revoked.
[ "$(grep -c 'kill token=' "$T/gw.log")" = 1 ] || { echo "FAIL: sessions left waiting for a resume"; cat "$T/gw.log"; exit 1; }
echo "no sessions left behind"

echo "== per-VM gateway that needs a daily TOTP unlock, via the generated ssh config"
# A second "VM": sshd on localhost only, its own gateway with --require-unlock.
/usr/sbin/sshd -D -e -f /dev/null -o ListenAddress=127.0.0.1:2224 -o HostKey="$T/hostkey" \
  -o HostCertificate="$T/hostkey-cert.pub" -o AuthorizedKeysFile="$T/authorized_keys" \
  -o PasswordAuthentication=no -o StrictModes=no -o PidFile=none 2>"$T/sshd2.log" &
"$T/portash" token add laptop --device "$DEVICE" --ttl 1h --dir "$T/gw2" >"$T/token2" 2>/dev/null
SECRET=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
echo "$SECRET" | "$T/portash" totp import laptop --unlock --dir "$T/gw2"
"$T/portash" gateway --dir "$T/gw2" --listen 127.0.0.1:8444 --network 127.0.0.1/32 --ports 2224 \
  --require-unlock 2>"$T/gw2.log" &
sleep 1
"$T/portash" login vm2 --gateway 127.0.0.1:8444 --pin "$("$T/portash" fingerprint --dir "$T/gw2")" <"$T/token2"
{ "$T/portash" ssh-config vm2
  printf 'Host vm2\n  Port 2224\n  User root\n  IdentityFile %s\n  IdentitiesOnly yes\n  BatchMode yes\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile /dev/null\n' \
    "$T/userkey" "$T/known_hosts"
} >"$T/ssh_config"
grep -q 'HostKeyAlias vm2' "$T/ssh_config" || { echo "FAIL: ssh-config has no HostKeyAlias"; exit 1; }
if ssh -F "$T/ssh_config" vm2 true 2>"$T/err"; then echo "FAIL: connected without unlocking"; exit 1; fi
grep -o 'unlock required.*' "$T/err"
python3 -I - "$SECRET" <<'PY' >"$T/code"
import base64, hmac, struct, sys, time
key = base64.b32decode(sys.argv[1])
h = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), "sha1").digest()
o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000))
PY
"$T/portash" unlock vm2 <"$T/code"
"$T/portash" status
for i in 1 2 3; do ssh -F "$T/ssh_config" vm2 "echo vm2 run $i ok"; done
echo "one code, then three connections without prompts (as Ansible would make)"
if "$T/portash" unlock vm2 <"$T/code" 2>"$T/err"; then echo "FAIL: reused code accepted"; exit 1; fi
echo "reused code refused: $(cat "$T/err" | head -1)"

echo "== gateway log"; cat "$T/gw.log"
echo PASS
