<p align="center"><img src="docs/brand/portash-logo.svg" width="280" alt="portash: HTTPS 443 SSH forwarder"></p>

# portash

*Porta* is Italian for door: portash is a door to your shells.

SSH to your VMs from anywhere: no public port 22, and it still works on hotel
Wi-Fi that blocks UDP. One small Go binary, zero third-party dependencies.

`portash` keeps OpenSSH and adds what it lacks: a hardened way in on TCP 443, and
control over what happens after login. One binary does both ends:

* **On each VM:** `portash gateway` listens on 443 (TLS 1.3, pinned key, tokens
  bound to one laptop, rate limits) and forwards only to the VM's own sshd on
  `127.0.0.1:22`. No VPN needed, nothing else exposed.
* **After login:** `portash shell` records sessions and can sandbox all writes;
  `portash restrict` limits a key to an allowlist, with TOTP-gated and deny rules;
  sudo asks for a TOTP code.
* **On the laptop:** `portash dial` is an OpenSSH `ProxyCommand`, so `ssh`, `scp`,
  `rsync`, Ansible and VS Code Remote work unchanged.

Running a Vabbit VPN is optional: with it, one gateway can serve many VMs and
portash goes direct over WireGuard when UDP works. See [docs/DESIGN.md](docs/DESIGN.md)
for the reasoning and security model, and the architecture and audit docs for diagrams.

## Set up: portash on each VM (no VPN, no extra server)

Each VM runs its own gateway on 443 that only reaches its own sshd. There is
no box in the middle, so one hacked VM doesn't open the others.

On **each VM**:

```sh
# sshd only on localhost; close 22 in the cloud firewall, open 443.
echo "ListenAddress 127.0.0.1" | sudo tee /etc/ssh/sshd_config.d/portash.conf
sudo systemctl restart ssh
sudo install dist/portash /usr/local/bin/
sudo portash gateway --network 127.0.0.1/32 --ports 22 --listen :443 --dir /var/lib/portash --require-unlock
sudo portash fingerprint --dir /var/lib/portash            # the pin laptops need
```

(or use `packaging/portash-gateway.service` with `--network 127.0.0.1/32 --require-unlock`).

Per laptop, the admin binds a token to the laptop's device key on each VM and
sets up the daily unlock. Enroll TOTP once, then import the same secret on the
other VMs, so one authenticator entry and one code unlock them all:

```sh
sudo portash token add alice-laptop --device pshd_... --dir /var/lib/portash      # on each VM
sudo portash totp enroll alice-laptop --unlock                                # on the first VM; prints otpauth://...
echo 'otpauth://...' | sudo portash totp import alice-laptop --unlock         # on every other VM
```

On the **laptop**, add each VM by name (the token comes from a prompt or
stdin, never a flag), then generate the ssh config:

```sh
portash device                                   # once; send the pshd_... key to the admin
portash login vm1.example.com --pin sha256:...   # once per VM
portash login vm2.example.com --pin sha256:...
portash ssh-config >> ~/.ssh/config              # a Host block per VM
portash unlock                                   # each morning: one TOTP code, all VMs, 12 hours
ssh vm1.example.com
```

`portash status` shows each VM and how long it stays unlocked. The ticket lives
only on this laptop and is bound to its token and device key; when it runs out,
open sessions close and `ssh` says to run `portash unlock`. Set the length with the
gateway's `--ticket-ttl` (default 12h).

### Ansible and other automation

Ansible uses your ssh config, so after `portash unlock` it reaches every VM with
no prompts:

```ini
# ansible.cfg
[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
pipelining = True
```

ControlPersist reuses one connection per host for the whole run. TOTP sudo
would ask for a code on every `become`, so give Ansible its own user with
passwordless sudo (key with `command="portash shell"`), protected by the daily
unlock, and keep TOTP sudo for people working by hand.

## Set up: with a Vabbit VPN

On each **VM** (already a Vabbit device): make sshd listen only on its VPN
address, and close 22 in the cloud firewall.

```sh
echo "ListenAddress 100.92.0.7" | sudo tee /etc/ssh/sshd_config.d/portash.conf
sudo systemctl restart ssh
```

On the **gateway** (a small public host on the VPN; preferably not the Vabbit
hub, which already sees relayed traffic), open TCP 443. If Vabbit's own 443
fallback already holds that port, use `--listen :8443` or skip the gateway (see
DESIGN.md, "Coexisting").

```sh
sudo install dist/portash /usr/local/bin/
sudo portash fingerprint --dir /var/lib/portash           # prints sha256:... for clients
# edit --network in the unit to your NETWORK_CIDR, then:
sudo cp packaging/portash-gateway.service /etc/systemd/system/
sudo systemctl enable --now portash-gateway
```

On your **laptop** (macOS, Linux or Windows):

```sh
portash device                      # prints pshd_... ; send it to the admin
```

The admin binds a token to that device (it is useless on any other machine)
and sends you the token:

```sh
sudo portash token add alice-laptop --device pshd_... --ttl 2160h --dir /var/lib/portash
```

Back on the laptop (the token is read from a prompt or stdin, never a flag):

```sh
portash login vpn --gateway gw.example.com --pin sha256:... --network 100.92.0.0/16
portash ssh-config vpn >> ~/.ssh/config    # then add Host/HostName lines per VM
ssh myvm
```

`portash dial -v` (in the ProxyCommand) prints which path was used. The direct path
is only tried when the OS routes the target through the VPN; otherwise portash
goes through the gateway, so a look-alike address on hotel Wi-Fi is never dialled.

Revoke a laptop with `sudo portash token rm alice-laptop --dir /var/lib/portash`. New
connections are refused at once and open sessions are cut within 5 seconds.
Tokens also expire (`--ttl`, default 90 days). The gateway caps connections
(512 total, 16 per token), closes streams idle for 10 minutes or older than
24 hours, and ignores an IP for 10 minutes after 10 failed attempts.

If the network drops (laptop sleep, new Wi-Fi, a hotel captive portal),
`portash dial` reconnects by itself and the ssh session carries on where it was,
for up to 10 minutes, with no tmux needed. `portash dial -v` prints when it
reconnects; `--no-resume` turns it off. The gateway's `--resume-window` sets
how long it waits.

To rotate the gateway key, give clients both pins (`--pin sha256:old,sha256:new`),
switch the gateway, then drop the old pin.

## Host keys

Don't trust a VM's host key the first time you see it; a compromised gateway
could impersonate the VM. Sign host keys with an offline CA instead:

```sh
ssh-keygen -t ed25519 -f host_ca                      # once, keep it offline
ssh-keygen -s host_ca -I myvm -h -n vm1.example.com,100.92.0.7 -V +52w /etc/ssh/ssh_host_ed25519_key.pub
echo "HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub" | sudo tee -a /etc/ssh/sshd_config.d/portash.conf
# on laptops:
echo "@cert-authority *.example.com,100.92.* $(cat host_ca.pub)" >> ~/.ssh/known_hosts
```

In per-VM mode every VM is `127.0.0.1` to ssh, so `portash ssh-config` sets
`HostKeyAlias` to the VM's name; put that name in the certificate (`-n`).

`portash ssh-config` already sets `StrictHostKeyChecking yes`, `ForwardAgent no`
and `PasswordAuthentication no`.

## After login: roles

Pick one per user or key in `authorized_keys` (or with `Match User` +
`ForceCommand` in sshd_config). All of them need the root daemon:

```sh
sudo portash authd     # TOTP checks, audit log, session recordings (packaging/portash-authd.service)
```

| Role | authorized_keys prefix | What they get |
| --- | --- | --- |
| Admin | `command="portash shell"` | Full shell, every session recorded, every command logged, sudo needs a TOTP code |
| Operator | `command="portash shell --sandbox --write ~/work"` | Full shell, recorded, but can only create, change or delete files in `/tmp`, `/var/tmp` and `~/work`; no sudo |
| Restricted | `restrict,command="portash restrict --policy FILE"` | Only allowlisted commands; some need a TOTP code |

**TOTP.** Enroll a user and scan the printed `otpauth://` link (or `qrencode -t ansiutf8` it):

```sh
sudo portash totp enroll alice
```

Secrets live in `/var/lib/portash/totp` (root only). Codes can't be reused, and 5
wrong codes lock the user for 15 minutes.

**TOTP sudo.** Put this first in `/etc/pam.d/sudo` (keep `@include common-auth`
after it if you want password and code; remove it for code only), and set
`Defaults timestamp_timeout=0` in sudoers to ask on every sudo:

```
auth required pam_exec.so expose_authtok quiet /usr/local/bin/portash pam-totp
```

**Sandbox.** `--sandbox` uses Landlock (Linux 5.13+), so the kernel itself
refuses writes outside the allowed directories. However the command is written
(`r''m`, base64, a script, vim, python), protected files can't be changed,
deleted or renamed. It also applies to everything the session starts. Reading
is not restricted. The session's own terminal is the only one it can write to,
so output can't skip the recording. sudo is disabled inside it.

**Recordings** are asciinema files in `/var/log/portash/sessions/<user>/`
(`asciinema play FILE`), and every session and command is in
`/var/log/portash/audit.log`, both written by authd as root. If authd is down,
sessions are refused (`--fail-open` to allow them anyway). For admins without
`--sandbox`, a determined user can write around the recording; the audit log
and auditd still see every command.

## Restrict what a key can run

For CI bots, on-call helpers or contractors, give a key an allowlist instead of a
shell. sshd enforces it, so it works the same direct or through the gateway.

`/etc/portash/policy/deploy` (root-owned, not group/other writable):

```
# One allowed command per line. Matching is per argument:
#   *    matches one argument (glob; doesn't cross "/")
#   ...  at the end matches any number of further arguments
# Wildcards never match an argument starting with "-": write flags out.
# Programs that can start a shell (bash, vim, less, python, sudo, find, ...)
# are refused, and docker/git/tar/rsync/... only with fixed arguments.
# "!unsafe <rule>" overrides that for a program you have checked.
# "!totp <rule>" asks for a TOTP code first (typed, or piped: echo 123456 | ssh vm cmd).
# "!deny <rule>" refuses matches even if another rule allows them; in deny
# rules wildcards also match flags and the program may be a pattern.
uptime
systemctl status ...
!totp systemctl restart nginx
journalctl -u nginx -n *
!deny * --force
```

Then prefix the key in `~/.ssh/authorized_keys` on the VM:

```
restrict,command="/usr/local/bin/portash restrict --policy /etc/portash/policy/deploy --name ci-bot" ssh-ed25519 AAAA... ci-bot
```

`restrict` also turns off port, agent and X11 forwarding and the PTY. If a key
gets a PTY, portash assumes `restrict` was forgotten and refuses to run. For a
whole group, use `Match Group deployers` + `ForceCommand` in sshd_config instead.
Test a rule with `portash restrict --policy FILE --check 'systemctl restart nginx'`.
Every allow and deny goes to the auth log (`journalctl -t portash-restrict`).

The command is executed directly, never through a shell, so `;`, `|`, `$(...)`
are plain characters. It runs with a fixed PATH and a scrubbed environment.
The linter catches the common shell escapes, but no list is complete: check
any program you allow for ways to start other programs. scp/sftp/rsync aren't allowed unless you add them, and
adding them gives file access to everything the user can read.

## Develop

```sh
make test        # unit tests: auth, device binding, expiry, pinning, limits, revocation, command policy, resume across drops
make e2e         # real sshd/ssh/scp: host CA, stolen token, restricted keys, network drop, revocation (needs openssh, root)
sudo ./scripts/e2e-server.sh   # TOTP sudo, recording, sandbox, TOTP rules; creates users, edits PAM: throwaway VM only
make sbom        # regenerate the CycloneDX SBOM and the dependency report in sbom/
```

CI runs all of these on every push, and fails if `sbom/` is out of date.

## Status

Prototype. Done: per-VM gateway, audit phase 1 hardening, roles with TOTP,
sandbox and recording, session resume, daily TOTP unlock, one gateway per VM.
Not yet: relay mode, device keys in the OS keychain,
signed releases.

## License

MIT, see [LICENSE](LICENSE). Dependencies and their licenses are listed in
[sbom/](sbom/README.md): none besides the Go standard library.
