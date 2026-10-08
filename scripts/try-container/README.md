# Try portash in a container

A throwaway test "VM" in a Podman (or Docker) container: sshd for one user
`tester`, the portash gateway and a Cloudflare quick tunnel. No Cloudflare
account, domain or open port. Everything is created fresh on every start.

Not covered here: authd, TOTP for sudo, recordings and the sandbox. Those need
a real Linux host with systemd; use a VM for them.

## 1. Build

From the repository root (Go is not needed; the image builds portash itself):

```sh
podman build -t portash-try -f scripts/try-container/Containerfile .
```

## 2. Run

On the laptop you will connect from, get the two keys the container needs:

```sh
portash device                  # prints pshd_...
cat ~/.ssh/id_ed25519.pub       # or: ssh-keygen -t ed25519 first
```

Then start the container (on the same machine or any other):

```sh
podman run --rm -it --name portash-try \
  -e DEVICE=pshd_... \
  -e SSH_KEY="$(cat ~/.ssh/id_ed25519.pub)" \
  portash-try
```

It prints the tunnel URL, a TOTP link for your authenticator app, and the
exact `portash login` command with the token. Follow those steps on the
laptop, then:

```sh
portash unlock
ssh -o StrictHostKeyChecking=accept-new tester@trytest   # first time only; later: ssh tester@trytest
```

The URL changes on every start, so log in again after restarting the
container (`portash logout trytest` first).

## Without Cloudflare

To test without the tunnel, run the gateway directly and publish its port:

```sh
podman run --rm -it -p 8443:443 -e MODE=direct \
  -e DEVICE=pshd_... -e SSH_KEY="$(cat ~/.ssh/id_ed25519.pub)" portash-try
```

The printed login uses `localhost:8443`; from another machine use
`HOSTNAME:8443` instead. Rootless Podman can publish 8443 without extra
setup.
