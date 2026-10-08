#!/usr/bin/env bash
# Server-side features with real sshd and sudo: recorded shells, the Landlock
# sandbox, TOTP-gated commands and TOTP sudo. It CREATES USERS and REPLACES
# /etc/pam.d/sudo while it runs (restored on exit), so run it only in a
# throwaway VM or container, as root. Needs go, openssh, sudo, python3.
set -euo pipefail
cd "$(dirname "$0")/.."
T=$(mktemp -d); chmod 755 "$T"
cp /etc/pam.d/sudo "$T/pam-sudo.bak"
PIDS=""
cleanup() {
  kill $PIDS 2>/dev/null || true
  cp "$T/pam-sudo.bak" /etc/pam.d/sudo; rm -f /etc/sudoers.d/portash-test
  for u in eg_alice eg_bob eg_ci; do userdel -r "$u" 2>/dev/null || true; done
  rm -rf "$T"
}
trap cleanup EXIT
go build -o "$T/portash" ./cmd/portash && chmod 755 "$T/portash"
SOCK="$T/run/authd.sock"

for u in eg_alice eg_bob eg_ci; do useradd -m -s /bin/bash "$u" 2>/dev/null || true; usermod -p "*" "$u"; done  # "*": no password, but not locked
"$T/portash" authd --socket "$SOCK" --totp-dir "$T/totp" --log-dir "$T/log" >/dev/null 2>"$T/authd.log" &
PIDS="$PIDS $!"
for u in eg_alice eg_ci; do "$T/portash" totp enroll "$u" --totp-dir "$T/totp" >"$T/$u.uri" 2>/dev/null; done
code() { # current TOTP code for a user (stands in for the phone app)
  python3 -I - "$(cat "$T/totp/$1.secret")" "${2:-0}" <<'PY'
import base64, hmac, struct, sys, time
key = base64.b32decode(sys.argv[1] + "=" * (-len(sys.argv[1]) % 8))
step = int(time.time()) // 30 + int(sys.argv[2])
h = hmac.new(key, struct.pack(">Q", step), "sha1").digest()
o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000))
PY
}

# TOTP sudo for alice: the code is typed at sudo's prompt, every time.
cat >/etc/pam.d/sudo <<PAM
auth required pam_exec.so expose_authtok quiet $T/portash pam-totp --totp-dir $T/totp
account include common-account
session include common-session-noninteractive
PAM
printf 'eg_alice ALL=(ALL) ALL\nDefaults:eg_alice timestamp_timeout=0\neg_bob ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/portash-test
chmod 440 /etc/sudoers.d/portash-test

ssh-keygen -q -t ed25519 -N '' -f "$T/hostkey"
for u in alice bob ci; do ssh-keygen -q -t ed25519 -N '' -f "$T/$u"; done
printf '!totp date\nuptime\n!deny uptime --help\n' >"$T/ci.policy"
mkdir -p "$T/keys"
echo "command=\"$T/portash shell --socket $SOCK\" $(cat "$T/alice.pub")" >"$T/keys/eg_alice"
echo "command=\"$T/portash shell --sandbox --write ~/work --socket $SOCK\" $(cat "$T/bob.pub")" >"$T/keys/eg_bob"
echo "restrict,command=\"$T/portash restrict --policy $T/ci.policy --socket $SOCK\" $(cat "$T/ci.pub")" >"$T/keys/eg_ci"
chmod 755 "$T/keys"; chmod 644 "$T/keys"/*
mkdir -p /run/sshd ~eg_bob/work && chown eg_bob ~eg_bob/work
/usr/sbin/sshd -D -e -f /dev/null -o ListenAddress=127.0.0.1:2223 -o HostKey="$T/hostkey" \
  -o AuthorizedKeysFile="$T/keys/%u" -o PasswordAuthentication=no -o StrictModes=no -o PidFile=none >/dev/null 2>"$T/sshd.log" &
PIDS="$PIDS $!"
sleep 1
S() { local who=$1; shift; ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR -i "$T/${who#eg_}" -p 2223 "$who@127.0.0.1" "$@"; }
fail() { echo "FAIL: $*"; exit 1; }

echo "== TOTP sudo (alice)"
out=$(S eg_alice "echo $(code eg_alice) | sudo -S -p '' id -un" 2>&1) || true
[ "$out" = root ] && echo "right code: sudo ran as root" || fail "sudo with right code: $out"
S eg_alice "echo 000000 | sudo -S -p '' true" >/dev/null 2>&1 && fail "sudo accepted a wrong code"
echo "wrong code: sudo refused"
S eg_alice "echo $(code eg_alice) | sudo -S -p '' true" >/dev/null 2>&1 && fail "sudo accepted a reused code"
echo "reused code: sudo refused"

echo "== recorded interactive session (alice)"
printf 'echo hello-$((6*7))\nexit\n' | S eg_alice -tt >/dev/null 2>&1 || true
sleep 0.5
rec=$(ls "$T"/log/sessions/eg_alice/*.cast | head -1)
grep -q 'hello-42' "$rec" && echo "recording $(basename "$rec") contains the session output" || fail "recording missing output"
S eg_alice -tt 'echo forced-$((5*5))' >/dev/null 2>&1 </dev/null || true
sleep 0.5
grep -lq 'forced-25' "$T"/log/sessions/eg_alice/*.cast && echo "ssh -t host cmd is recorded too" || fail "ssh -t with a command was not recorded"

echo "== sandboxed shell (bob)"
S eg_bob 'touch ~/work/ok /tmp/ok && echo writes to ~/work and /tmp: ok'
S eg_bob 'echo x >> ~/.bashrc' 2>/dev/null && fail "bob wrote ~/.bashrc"
echo "write to ~/.bashrc: denied"
S eg_bob 'mkdir -p ~/.ssh && echo x >> ~/.ssh/authorized_keys' 2>/dev/null && fail "bob planted an ssh key"
echo "planting an ssh key: denied"
S eg_bob 'sudo -n true' 2>/dev/null && fail "sudo worked inside the sandbox"
echo "sudo inside the sandbox: denied (no_new_privs)"
out=$(printf 'echo bypass > $SSH_TTY; echo rc=$?\nexit\n' | S eg_bob -tt 2>&1 | tr -d '\r' | grep '^rc=' || true)
[ "$out" != rc=0 ] && echo "writing past the recording to sshd's terminal: denied ($out)" || fail "recording bypass possible"

echo "== TOTP-gated command (ci)"
out=$(echo "$(code eg_ci)" | S eg_ci date 2>/dev/null) && echo "date with code: $out" || fail "date with right code"
echo 000000 | S eg_ci date >/dev/null 2>&1 && fail "date with wrong code"
echo "date with wrong code: denied"
S eg_ci uptime >/dev/null && echo "uptime (no TOTP rule): allowed"
S eg_ci uptime --help >/dev/null 2>&1 && fail "deny rule ignored"
echo "uptime --help (deny rule): denied"

echo "== audit log"
sed 's/^/  /' "$T/log/audit.log"
echo PASS
