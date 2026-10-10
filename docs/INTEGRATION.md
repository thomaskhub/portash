# Using portash from Ansible and Terraform

This page covers the basic flow only: SSH to a VM through a Cloudflare tunnel,
a pinned gateway, a token bound to the admin's laptop and the daily TOTP unlock.
sudo TOTP, session recording and restricted keys are optional and not needed here.

## What you automate

| Where | What | Command |
|---|---|---|
| Admin laptop, once per VM | make the gateway key, pin, token, unlock secret and the bundle | `portash provision create VM --gateway https://HOST --ssh-user USER` |
| VM, every provisioning run | write them into `/var/lib/portash` | `portash provision apply -` |
| Admin laptop, once | take the grant, unlock, connect | `portash join VM/admin.grant; portash unlock; ssh ...` |

Both commands are safe to repeat. Nobody logs in to the VM to make access.

## Secrets: what goes where

| Item | Secret? | Keep it | Never |
|---|---|---|---|
| `provision.bundle` | yes (gateway private key, unlock secret) | SSM Parameter Store / Vault / kilovault | in `user_data`, in git, in Terraform state |
| Cloudflare tunnel token | yes | same store, root-only file `/etc/cloudflared/token.env` | on a command line, in a world-readable unit file |
| `admin.token` (client token) | yes | the admin's laptop only | on any VM (the VM holds only its hash) |
| Pin `sha256:...` | no | anywhere (it is in the grant) | |

Terraform's state holds `user_data` in plain text and the cloud API returns it,
so `user_data` carries only a fetch command, never the bundle.

## Terraform: user_data

The first-boot script only fetches secrets and applies them. Example for AWS:

```sh
#!/usr/bin/env bash
set -euo pipefail
BUNDLE=$(aws ssm get-parameter --with-decryption --name /vm1/portash-bundle --query Parameter.Value --output text)
TUNNEL=$(aws ssm get-parameter --with-decryption --name /vm1/tunnel-token --query Parameter.Value --output text)
install -d -m 700 /var/lib/portash /etc/cloudflared
(umask 077; printf 'TUNNEL_TOKEN=%s\n' "$TUNNEL" > /etc/cloudflared/token.env)
printf '%s' "$BUNDLE" | portash provision apply - --dir /var/lib/portash
systemctl enable --now portash-gateway cloudflared-portash
```

The instance role needs `ssm:GetParameter` on those two parameters only.
Create the bundle on the admin laptop with `provision create`, then put it into
the store (`aws ssm put-parameter --type SecureString --name /vm1/portash-bundle --value "$(cat vm1/provision.bundle)"`).
Terraform can create the tunnel (`cloudflare_tunnel`); its token is a secret
output, so write it to the store from a trusted machine, not from user_data.

## Ansible: role sketch

```yaml
- name: portash binary (checksum pinned)
  ansible.builtin.get_url:
    url: "{{ portash_mirror }}/{{ portash_version }}/portash_{{ portash_version | regex_replace('^v','') }}_linux_{{ portash_arch }}.tar.gz"
    dest: /tmp/portash.tgz
    checksum: "sha256:{{ portash_sha256 }}"
- ansible.builtin.unarchive: { src: /tmp/portash.tgz, dest: /usr/local/bin, remote_src: true, include: [portash], mode: "0755" }

- name: state directory
  ansible.builtin.file: { path: /var/lib/portash, state: directory, mode: "0700" }

- name: apply the prepared access (bundle comes from your vault)
  ansible.builtin.command: portash provision apply - --dir /var/lib/portash --json
  args: { stdin: "{{ portash_bundle }}" }
  no_log: true
  register: prov
  changed_when: "(prov.stdout | from_json).items | selectattr('status','ne','unchanged') | list | length > 0"
  notify: restart portash-gateway   # only needed if the units are new; the gateway re-reads tokens.d itself

- name: systemd units (gateway, cloudflared) are templates from packaging/
  ...
```

Notes:
* `no_log: true` is needed: stdin holds the bundle.
* `--json` prints `{"dryRun":false,"pin":"sha256:...","items":[{"item":"token admin","status":"created|updated|unchanged"}]}`.
  Exit code 0 = applied or nothing to do, 1 = refused (bad bundle, different key already present). It never prints a secret.
* `--dry-run` shows what would happen and writes nothing; use it for check mode.
* Run the role as root; the files take the owner of `/var/lib/portash`.
* Use `packaging/portash-gateway.service` and `packaging/portash-cloudflared.service` as the unit templates.
  On an IPv6-only VM add `--edge-ip-version 6` to the cloudflared command.

## Everyday changes (after the first run)

* **Add a person:** on your admin machine, with their device key (`portash device` on their laptop):
  `portash token new alice-laptop --device pshd_... --ttl 2160h --out alice.token`. It prints one line
  (`name hash device=... expires=...`, safe to keep in a repository); deliver it to the VM as
  `/var/lib/portash/tokens.d/alice-laptop`, one file per person, and give Alice `alice.token` once.
  The gateway picks the file up within seconds, no restart. Details: README, "Tokens from files".
* **Remove a person:** delete their `tokens.d` file. New connections are refused at once; open ones are cut in about 5 s.
* **Renew a token:** make a new one with `token new` and write the new line over the file. `--ttl 0` never expires; prefer a lifetime.
* **Health:** `portash gateway-status [--json]` on the VM (what the gateway folder holds, tokens and unlock secrets, the pin). Fields: see README, "What is in a gateway's folder".

## Gotchas

* The grant's gateway must be `https://HOST` for a Cloudflare tunnel. `HOST:443` pins Cloudflare's own
  certificate and fails with `gateway key mismatch`.
* The gateway key is never replaced by `apply`: every user's pin would change. To rotate it on purpose,
  remove `gateway.key`/`gateway.crt`, create a new bundle in a new folder and hand out new grants.
* Keep the cloud console (or another path) as break-glass until the tunnel has run for a while.
* The unlock secret is separate from the sudo OTP: this flow has no sudo OTP.

## What this flow does not include (on purpose)

sudo TOTP, session recording and `command="portash shell"` roles are documented in the README
under Roles, TOTP sudo and Restricted keys. They are optional and can be added later without changing
the tunnel flow.
