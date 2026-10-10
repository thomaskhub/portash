#!/usr/bin/env bash
# TOTP for sudo on this VM (portash pam-totp, "code only"). Safe to run again. Needs portash >= rc.4 installed.
# Usage on the VM, as the user that gets the OTP:  bash sudo-otp.sh [USER]     (default: you)
# KEEP A SECOND ROOT SHELL OPEN (sudo -i in another ssh session) until you tested it.
set -euo pipefail
U=${1:-$(id -un)}
SUDO=""; [ "$(id -u)" = 0 ] || SUDO=sudo
$SUDO true
command -v portash >/dev/null || { echo "portash is not installed"; exit 1; }
PAM=/etc/pam.d/sudo

echo "== enroll $U (the code is separate from the daily unlock)"
if $SUDO sh -c 'ls /var/lib/portash-authd/totp 2>/dev/null' | grep -q "^$U"; then
  echo "already enrolled: your authenticator entry for sudo keeps working"
else
  $SUDO install -d -m 700 /var/lib/portash-authd /var/lib/portash-authd/totp
  $SUDO portash totp enroll "$U"
  echo ">> scan the link/QR above NOW, then press Enter"; read -r _
fi

echo "== sudoers: ask on every sudo, and no NOPASSWD for $U"
$SUDO tee /etc/sudoers.d/zz-portash-totp >/dev/null <<SUD
Defaults timestamp_timeout=0
$U ALL=(ALL:ALL) ALL
SUD
$SUDO chmod 440 /etc/sudoers.d/zz-portash-totp
$SUDO visudo -cf /etc/sudoers.d/zz-portash-totp >/dev/null || { $SUDO rm -f /etc/sudoers.d/zz-portash-totp; echo "sudoers check failed, removed"; exit 1; }

echo "== PAM"
[ -f $PAM.before-portash ] || $SUDO cp -p $PAM $PAM.before-portash
$SUDO tee $PAM >/dev/null <<'PAM'
auth required pam_exec.so expose_authtok quiet /usr/local/bin/portash pam-totp
account include common-account
session include common-session-noninteractive
PAM
cat <<TXT

done. Test in a SECOND session (keep this one open):
  sudo -k; sudo true        -> asks "Password:", type the 6-digit code
Undo:  sudo cp -p $PAM.before-portash $PAM ; sudo rm /etc/sudoers.d/zz-portash-totp
TXT
