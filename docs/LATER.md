# Later: sudo TOTP and logging (not part of the tunnel-only rollout)

Status: prepared, not tested on a real VM. Decision (2026-10-10): roll out the tunnel-only flow first
(docs/INTEGRATION.md), let it run for a few versions, then add this.

## Add when
A second admin, a contractor, or a need for an audit trail.

## Pieces
1. **sudo TOTP**: `scripts/vm-sudo-totp.sh [USER]`. Enrolls a sudo secret, adds
   `/etc/sudoers.d/zz-portash-totp` (`timestamp_timeout=0`, no NOPASSWD for the user) and the
   "code only" PAM line `auth required pam_exec.so expose_authtok quiet /usr/local/bin/portash pam-totp`.
   Needs no authd. Keep a second root shell open while testing. Undo: restore `/etc/pam.d/sudo.before-portash`
   and delete the sudoers file.
2. **Ansible**: plain `ssh host sudo cmd` has no terminal and is refused; give Ansible its own user with
   passwordless sudo (README, "Ansible").
3. **Logging and recording**: `portash-authd` (`packaging/portash-authd.service`), `command="portash shell"` in the
   user's authorized key, keys in a root-owned `AuthorizedKeysFile`. Not scripted yet.
4. **Gateway as its own user**: the reference VM script runs the gateway as root; the packaged unit uses the
   `portash` user. Switch when authd is added (authd secrets must be unreadable by the gateway).

## Open
* Provision-apply style command for sudo secrets (create on the laptop, apply on the VM), like `provision`.
* Test on a real VM with Lightsail's default NOPASSWD admin, and on a user without a password.
