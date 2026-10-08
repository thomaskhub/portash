# portash: SSH that gets through port 22 and UDP blocks

## The problem

DevOps work on cloud VMs from a laptop. Two things get in the way:

1. **Port 22 is blocked or unwanted.** Many networks block outbound 22, and an
   internet-facing sshd on a VM is a constant brute-force target.
2. **UDP is blocked.** Hotel and conference Wi-Fi often allow only TCP 80/443.
   That kills WireGuard (and therefore Vabbit), mosh, QUIC and anything
   "direct UDP".

So the only transport that works *everywhere* is **TLS on TCP 443**. Any design
that doesn't have a 443 path fails the hotel case.

## Options compared

| Option | Gets past port 22 block | Works when UDP blocked | Security | Keeps scp/rsync/Ansible/VS Code | Verdict |
|---|---|---|---|---|---|
| Plain SSH inside the Vabbit VPN | Yes (22 never public) | **No** (WireGuard is UDP) | Excellent (WireGuard + OpenSSH) | Yes | Best path *when UDP works* |
| mosh | No (needs SSH to start) | **No** (UDP 60000+) | Good | No (shell only) | Solves roaming, not blocking |
| Custom shell over direct UDP | Yes | **No** | We'd own the crypto | No | Rejected |
| Custom shell over MQTT (broker on 443/WSS) | Yes | Yes | Broker becomes a dependency; we'd own E2E crypto | No | Rejected: a pub/sub bus is the wrong shape for an interactive byte stream (extra hop, QoS/ordering/flow control to fight), and it's strictly more parts than a direct 443 stream |
| Rewrite SSH ("modern shell" protocol) | Yes | Depends | Auth and crypto are where the bugs live | No | Rejected: no win over OpenSSH |
| **OpenSSH tunnelled over TLS 443, through the Vabbit hub, direct over WireGuard when it's up** | Yes | **Yes** | OpenSSH end to end; the gateway only sees ciphertext | **Yes** | **Recommended** |

## Recommendation: fix the transport, keep SSH

Don't replace SSH. It's the part that's already right (auth, host keys, agent,
scp/sftp/rsync, Ansible, VS Code Remote, port forwarding). What's broken is how
packets reach it. `portash` is a tiny, zero-dependency Go binary that only moves
bytes:

```
                   UDP ok:   laptop ──WireGuard (Vabbit)──────────▶ VM 100.92.0.7:22
laptop (ssh) ─┤
                UDP blocked: laptop ──TLS :443──▶ hub (portash gateway) ──WireGuard──▶ VM 100.92.0.7:22
```

* **VMs expose nothing.** sshd listens only on the VPN address (or the cloud
  firewall drops 22). No VM needs a public port at all.
* **The Vabbit hub** (already public, already on the VPN) runs
  `portash gateway` on TCP 443. It accepts a TLS connection, checks an `psh_`
  token, and splices the stream to `VPN-IP:22`. Nothing else.
* **The laptop** uses `portash dial` as an OpenSSH `ProxyCommand`. It first tries
  the VPN address directly (fast path when Vabbit is up); if that doesn't
  connect within ~1.5s it goes through the gateway on 443.

Then `ssh`, `scp`, `rsync -e ssh`, Ansible and VS Code all just work, unchanged.

## Security model

Two independent layers, so a failure in one doesn't expose the VM:

1. **Gateway gate (who may reach sshd at all).**
   * TLS 1.3 only. The gateway uses a self-signed key generated on first run and
     the client **pins its SHA-256 fingerprint** (no CA to trust or rotate; a
     real certificate can be supplied instead with `--cert/--key`).
   * Each laptop gets a 256-bit `psh_` token bound to that laptop's Ed25519
     device key. Every request is signed by the device key over the TLS
     session's exported keying material (RFC 8446 exporter), so a copied token
     is useless elsewhere and a captured request can't be replayed. The gateway
     stores only SHA-256 hashes and public keys (file 0600), compares in
     constant time, and tokens expire (default 90 days). Revoking a token
     refuses new connections at once and cuts open sessions within 5 seconds.
   * Unauthenticated requests get a bare 404, so scanners see an ordinary web
     server.
   * Targets are restricted to the **network CIDR** and an **allowed port list**
     (default `22`). The gateway can't be used as an open proxy into anything else,
     including its own loopback or the cloud metadata service.
2. **SSH (who may log in).** Unchanged OpenSSH: keys only, host key checking.
   The gateway carries ciphertext it can't read or tamper with.

Other details: 512 connections in total and 16 streams per token; streams idle
for 10 minutes or older than 24 hours are closed; an IP is ignored for 10
minutes after 10 failed attempts; every connect, deny and kill is logged.
The client only tries the direct path when the OS routes the target through
the VPN, so a look-alike 100.x address on hotel Wi-Fi is never dialled, and
`portash ssh-config` turns on strict host key checking (use a host CA).

## Per-VM mode (no VPN)

The gateway can run on each VM with `--network 127.0.0.1/32 --ports 22`, so it
only ever forwards to that VM's own sshd, which listens on localhost. Every
gateway protection applies unchanged. There is no shared middle box to
compromise, and the Vabbit VPN becomes an optional add-on.

The laptop keeps one named gateway per VM (`portash login NAME`), and
`portash ssh-config` writes a Host block per VM with `HostName 127.0.0.1` and
`HostKeyAlias NAME`, so host keys and certificates stay per VM. No relay is
needed: a VM without a public IP can be reached through any VM that has one,
by running that VM's gateway with `--network` set to the private subnet.

## After login: roles, TOTP, sandbox, recording

Scanning what a user types can't stop an attack: in an interactive shell,
`r''m`, base64, aliases, editors and scripts all defeat a text filter, and the
gateway only sees ciphertext anyway. So portash enforces at the points that see
the real action:

* **portash authd** is a small root daemon on a Unix socket. Sessions run as the
  user and can't read TOTP secrets or write tamper-proof logs, so they ask
  authd. It identifies callers by the kernel's peer credentials
  (SO_PEERCRED), keeps TOTP secrets in a root-only directory, refuses reused
  codes, locks a user out for 15 minutes after 5 wrong codes, and writes the
  audit log and session recordings as root.
* **TOTP sudo** uses the stock `pam_exec` module to call `portash pam-totp`, so
  root actions need a fresh code (each time with `timestamp_timeout=0`).
* **portash shell --sandbox** applies Landlock before the shell starts: the kernel
  refuses to create, change, delete or rename anything outside the allowed
  directories, for the shell and everything it starts, root included.
  `no_new_privs` comes with it, so sudo can't be used to escape.
* **Recording**: portash shell puts the session on a new pseudo-terminal and
  copies its output to authd (asciinema format). In sandbox mode, the outer
  terminal is not writable, so output can't skip the recording.
* **portash restrict** adds `!totp` rules (a code is read from stdin before the
  command runs) and `!deny` rules that win over every allow rule.

## Command restrictions

The gateway can't see commands (it only carries SSH ciphertext), so restriction
lives on the VM where sshd decrypts them. `portash restrict` is an OpenSSH forced
command: sshd runs it instead of what the client asked for and passes the
request in `SSH_ORIGINAL_COMMAND`. It splits that with shell-style quoting but
no expansion, matches it per argument against an allowlist, and `execve`s the
program from a fixed PATH with a scrubbed environment, so there's no shell to
inject into. Wildcards never match arguments starting with `-`, which closes
the usual escape of slipping in an option such as `--upload-pack=` or
`-o ProxyCommand=`. Policies are per key (`command=` in authorized_keys) or per
user/group (`ForceCommand`), and every decision goes to syslog `LOG_AUTH`.

The limit of any allowlist is the programs on it: anything that can spawn a
process (editors, pagers, interpreters, `docker run`, `sudo`) turns it back
into a shell. That's documented, not enforced.

## Why HTTP Upgrade on 443 (not raw TLS, not WebSocket)

The client sends `GET /v1/tcp?target=100.92.0.7:22` with `Upgrade: portash` over
TLS; the gateway answers `101 Switching Protocols` and both sides switch to a
raw byte stream. This looks like normal HTTPS to middleboxes, can run behind an
ordinary HTTPS reverse proxy that supports upgrades, and needs only the Go
standard library. The client also honours `HTTPS_PROXY` (HTTP CONNECT) for
networks that force a proxy.

## Daily unlock (TOTP once, then no prompts)

With `--require-unlock`, every stream needs a ticket. `portash unlock` sends a
TOTP code with the token over the pinned TLS connection, signed by the device
key like any request (the signed target is `portash-unlock`). The gateway checks
the code against the secret enrolled for that token (replays refused, 5 wrong
codes lock the token for 15 minutes) and returns a random 256-bit ticket that
expires after 12 hours. The gateway keeps only its hash, bound to the token,
in a 0600 file so tickets survive a restart.

Each stream request carries the ticket. A missing, expired or someone else's
ticket gets 401 and the client says to run `portash unlock`. When a ticket runs
out, the sweep closes its open streams. Because each per-VM gateway checks the
code itself, the same secret can be imported on every VM: one authenticator
entry, one code each morning, all VMs unlocked, and still no shared server.

This is the gate for automation: ssh, scp, rsync, Ansible and VS Code need
no prompt during the day, and a stolen laptop is useless without the phone
once the ticket expires. TOTP sudo stays for people working by hand.

## Session resume (sleep, Wi-Fi changes)

ssh can't survive its TCP connection dying, so portash keeps that connection
away from the network. ssh talks to `portash dial` over a pipe, and the gateway
talks to sshd over localhost; only the stretch between `portash dial` and the
gateway crosses the network, and that stretch can be replaced.

* A stream opened with `Portash-Resume: new` gets a 256-bit session id back.
* Both ends keep what they sent until the other side acknowledges it (up to
  4 MiB; writing pauses beyond that). Frames are data, ack, keepalive,
  half-close and "session over".
* Keepalives every 5 s; a connection with no frames for 15 s (30 s at the
  gateway) is treated as dead. After the laptop wakes from sleep the client
  notices the jump in the wall clock and reconnects at once.
* The client reconnects with backoff (0.25 s up to 5 s) for up to 10 minutes,
  with a new TLS connection, the same token and a fresh device signature,
  plus the session id. Both sides say how many bytes they have received and
  resend the rest, so nothing is lost or doubled.
* The gateway holds the connection to sshd for `--resume-window` (10 min).
  A resume must come from the same token for the same target, so a leaked
  session id is useless alone. Revocation, the session limits and the stream
  cap apply as before.
* When ssh exits or kills `portash dial`, dial tells the gateway the session is
  over, so nothing waits for a resume that will never come.
* `portash ssh-config` sets `ServerAliveInterval 30` and `ServerAliveCountMax 20`
  so ssh itself waits out a 10-minute outage. If sshd has
  `ClientAliveCountMax` set low, raise it the same way.

Limits: a gateway restart ends all sessions (resume gets 410 Gone and ssh
exits), and the direct VPN path doesn't resume (Vabbit already roams).

## What it deliberately doesn't do (yet)

* **Token check against Vabbit.** Gateway tokens are separate from Vabbit
  device tokens. Later, the gateway could accept an Vabbit device token and
  verify it against the control plane, so removing a device also cuts its 443
  access.
* **Names.** Targets are VPN IPs; give them names in `~/.ssh/config`.

## Coexisting with Vabbit's own TCP 443 fallback

Vabbit is adding WireGuard over TLS on TCP 443 at the hub for networks that
block UDP. Once that lands, the laptop stays on the VPN even in a UDP-blocking
hotel, so **plain `ssh <vpn-ip>` covers the main use case** and the portash
gateway becomes optional. portash is still useful for:

* machines that aren't Vabbit devices (a borrowed laptop, CI runners) but
  hold an `psh_` token, and
* reaching one VM without bringing the whole VPN up.

Both want 443 on the hub, so they can't both bind it. In order of preference:

1. **Don't run the portash gateway** if Vabbit's fallback is enough.
2. **Run it on another port** (`--listen :8443`). Most hotel networks allow any
   outbound TCP port that isn't 22/25, but 443 is the only safe bet.
3. **Share 443** behind Vabbit's listener: it routes upgrade requests for
   `/v1/tcp` (or a separate SNI name) to portash on `127.0.0.1:8443`. That needs
   a hook on the Vabbit side, so it's for the Vabbit thread to decide.
