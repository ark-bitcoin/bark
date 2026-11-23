Scuttle mainnet deployment (jungle-prod)
========================================

Build and deploy tooling for the Scuttle mainnet servers. Scuttle changes
often, so the process is deliberately small: bash, rsync, ssh, nix.

Everything runs **from the build host `ark-build`**. After the Proxmox firewall
is on, only ark-build accepts SSH from the LAN and the other VMs are reached
over the private backend network.


# Topology

All VMs are Debian 12. `10.42.0.0/24` is the private Proxmox VXLAN network
(MTU 1450, no gateway).

| VM | LAN | backend | role |
|---|---|---|---|
| ark-build | 192.168.128.145 | 10.42.0.30 | nix builds, release store, deploy source |
| ark-captaind | 192.168.128.147 | 10.42.0.20 | `captaind` |
| ark-watchmand | 192.168.128.146 | 10.42.0.21 | `watchmand` |
| ark-cln | 192.168.128.151 | 10.42.0.22 | `lightningd` + cln-grpc + hold plugin, Tor package |
| (Patroni) | | 10.42.0.10 (VIP) | Postgres, managed separately |
| (bitcoind) | 192.168.128.172 | | Core, `:8332` |

```
                      ssh+rsync over 10.42 (deploy key)
 GitHub ---https---> ark-build ----------------------------> ark-captaind  10.42.0.20
                     nix build                               ark-watchmand 10.42.0.21
                     /srv/scuttle/releases/<commit>/         ark-cln       10.42.0.22

 captaind --mTLS grpc--> cln:9736, hold:9737 (ark-cln, 10.42.0.22)
 captaind, watchmand, lightningd --> Postgres 10.42.0.10 (captaind, watchmand), bitcoind 192.168.128.172:8332
```

Listeners (nothing binds `0.0.0.0`):

| Service | Address | Purpose |
|---|---|---|
| captaind | 10.42.0.20:3535 | public Ark gRPC (future ingress over a tunnel, behind a rate-limiting proxy) |
| captaind | 127.0.0.1:3536 | admin gRPC (unauthenticated by design) |
| captaind | 127.0.0.1:3537 | integration gRPC |
| watchmand | 127.0.0.1:4536 | admin gRPC |
| lightningd | 127.0.0.1:9735 | lightning P2P (loopback until the Tor/public-address decision) |
| cln-grpc | 10.42.0.22:9736 | captaind's CLN client (mTLS) |
| hold | 10.42.0.22:9737 | captaind's hold-invoice client (mTLS) |

Firewall note: after the firewall, ark VMs egress only to 53, 123 and 443.
Everything here uses https (GitHub, releases.nixos.org, cache.nixos.org,
static.crates.io, gitlab.com, Debian's https mirror). Backend traffic on 10.42
and the bitcoind RPC (192.168.128.172:8332) must be allowed explicitly.


# Layout

In this repository, `contrib/deploy/jungle-prod/`:

| Path | Purpose |
|---|---|
| `build.sh` | build a release for a git ref (on ark-build) |
| `deploy.sh` | copy a release to hosts and flip `/opt/scuttle/current` |
| `rollback.sh` | flip `/opt/scuttle/current` back |
| `setup-host.sh` | one-time host preparation: packages, users, dirs, units, config templates |
| `bootstrap-build-host.sh` | one-time ark-build setup: nix, checkout, deploy key |
| `lib/common.sh` | host inventory and helpers |
| `hosts/<role>/` | systemd units and config templates |
| `nix/hold-plugin.nix` | builds the pinned hold plugin for Debian |
| `keys/` | pinned CLN release signer keys and fingerprints |

On ark-build: `/srv/scuttle/src` (checkout), `/srv/scuttle/releases/<commit>/`,
`/srv/scuttle/vendor/` (verified CLN downloads), `/srv/scuttle/logs/`. The
scripts run from `/srv/scuttle/src/contrib/deploy/jungle-prod/`
(`git -C /srv/scuttle/src pull` to update them). They do not need the build
checkout to be at the commit being built.

On each target: `/opt/scuttle/releases/<commit>/`, `/opt/scuttle/current`
(symlink to the active release), `/opt/scuttle/previous` (the one before).


# Day-to-day

Until these files are committed and pushed, the scripts live in
`/srv/scuttle/deploy-dev/` on ark-build (copied from a working tree); use that
directory in place of `/srv/scuttle/src/contrib/deploy/jungle-prod`.

Reaching the VMs from the laptop: ark-build on its LAN address; the others
through it over 10.42, `ssh -i ~/.ssh/id_mbp_ed25519 -o IdentitiesOnly=yes
-J debian@192.168.128.145 debian@10.42.0.20` (.21 watchmand, .22 cln) (the
jump needs the same key accepted on ark-build).

Run these on ark-build (`ssh -i ~/.ssh/id_mbp_ed25519 debian@192.168.128.145`
from the laptop).

```
cd /srv/scuttle/src/contrib/deploy/jungle-prod
git -C /srv/scuttle/src pull --ff-only https://github.com/SatoshiPortal/scuttle.git scuttle   # refresh scripts

# Build. The ref is a branch, tag or commit. Default: scuttle.
./build.sh scuttle                    # -> /srv/scuttle/releases/<40-hex commit>/
./build.sh --force <ref>              # rebuild an existing release

# Deploy. Stages the files and flips the symlink, does NOT restart.
./deploy.sh latest captaind watchmand cln
./deploy.sh <commit-prefix> captaind          # one role
./deploy.sh --restart latest watchmand        # flip and restart the unit
./deploy.sh --keep 10 latest all              # keep 10 releases on the target (default 5)

# Roll back (instant: a symlink flip). Without --restart the old binary keeps
# running until you restart the unit.
./rollback.sh captaind                        # back to /opt/scuttle/previous
./rollback.sh --restart captaind <commit>     # to a specific release still on the host
```

Properties:

- **Idempotent.** Building an existing commit is a no-op; deploying a release
  that is already current changes nothing; the transfer is skipped when the
  verified release is already on the host.
- **Atomic.** The release is copied to `<commit>.partial`, checksum-verified on
  the target, renamed, then `current` is switched with `ln` + `mv -T`.
- **Safe by default.** Nothing restarts without `--restart`. Before flipping,
  deploy runs the new binary's `check-config` against the live
  `/etc/captaind/captaind.toml` or `/etc/watchmand/watchmand.toml` and refuses
  to flip if the config is not valid for the new release (for example a new
  required key). Update the config first.
- **Retention.** The newest N releases (default 5) stay on a target, never
  `current` or `previous`. ark-build keeps 10 (`KEEP_BUILD_RELEASES`).
- **Provenance.** `MANIFEST` in each release records: commit, flake.lock
  SHA-256, build date, `captaind --version` and `watchmand --version`, the CLN
  and hold pins, and the SHA-256 of each binary. `SHA256SUMS` (in every role
  directory and at the release root) covers every file.

A release is `releases/<commit>/{captaind,watchmand,cln}/`; each role directory
is what lands in `/opt/scuttle/releases/<commit>/` on that host:

```
captaind/bin/captaind
watchmand/bin/watchmand
cln/usr/{bin,libexec,share}     upstream CLN release tree (lightningd, cln-grpc, ...)
cln/plugins-extra/hold          the hold plugin
```

The build does not touch the repository: nothing is committed or pushed by
these scripts.


# The CLN approach

captaind needs from CLN (see `server/src/config.rs`, `server/src/ln/`):

- lightningd with the **cln-grpc** plugin, reached over mTLS gRPC;
- the **hold** plugin (`ark-bitcoin/hold` on GitLab), a second mTLS gRPC
  endpoint used for hold invoices (`hold_invoice.*` in `[[cln_array]]`);
- client certs: both plugins generate their own CA and client certificate in
  the lightning dir on first start. captaind reads `ca.pem`, `client.pem` and
  `client-key.pem` of each.

The pins live in `nix/dev-shell.nix`: CLN `26.06.10`, hold revision
`efc7d5f50470ed9d87b2b3b9c99c049da72de91a`. `build.sh` reads them from the
commit being built, so the deployed versions follow the pins by construction.

**lightningd and cln-grpc: the upstream release binaries.** The
`clightning-v26.06.10-Ubuntu-22.04-amd64.tar.xz` release contains lightningd,
its subdaemons and the bundled cln-grpc plugin. It needs glibc 2.35 or older
(Debian 12 has 2.36) and the libs `libsodium23`, `libsqlite3-0` and `libpq5`,
which Debian packages. The build verifies it before use:

1. the release `SHA256SUMS` has valid signatures from at least 3 distinct
   release signers pinned in `keys/` (the 6 signers of v26.06.10: ngoline,
   daywalker90, jaonoctus, Lagrang3, Christian Decker, the CLN release key;
   the pin was taken from ElementsProject/lightning `contrib/keys` and should be
   cross-checked out of band);
2. the tarball hash matches the signed `SHA256SUMS`;
3. the `clightning-v26.06.10.zip` hash in the signed file equals the hash that
   `nix/dev-shell.nix` pins for the zip it builds from. The tests and the
   deployment therefore run the same source release.

**hold: built with nix, repackaged for Debian.** There is no hold release
binary. `nix/hold-plugin.nix` builds the plugin from the revision and hash
pinned in the commit's `nix/dev-shell.nix` (the same source the integration
tests use). The dev shell's own derivation cannot be reused: nixpkgs builds
against glibc 2.44, whose headers turn `strtol`/`sscanf` into
`__isoc23_strtol`/`__isoc23_sscanf` (GLIBC_2.38), and Debian 12 has glibc 2.36.
The build links two tiny forwarding definitions of those symbols into the plugin
(they differ from the plain functions only in accepting `0b` binary prefixes),
and rewrites the ELF interpreter, rpath and sqlite soname to the host's libc,
libpq5 and libsqlite3-0. `build.sh` fails the build if the plugin needs any
glibc symbol newer than 2.36; `MANIFEST` records the needed libs and the highest
symbol (currently GLIBC_2.34). If a future nixpkgs bump adds other newer
symbols, the build stops there and this needs revisiting (the fallbacks are a
static musl build or shipping a glibc).

Why not the alternatives: building CLN from source on ark-build needs a C
toolchain and a pile of dev packages for no gain over a signed upstream build
of the same source; `nix copy` of the closure needs nix (or a copy of
`/nix/store`) on ark-cln, which we want to keep out of the CLN VM, and ties its
runtime to the store path layout. The one deviation from the test build is that
lightningd is upstream's Ubuntu build, not nixpkgs'; same version, same source
zip, different compiler and libs.


# First-time setup

Done once per environment. The state below is what the initial staging did; the
open steps are for the human.

## 1. ark-build

```
# as debian on ark-build
curl -fsSLO https://raw.githubusercontent.com/SatoshiPortal/scuttle/scuttle/contrib/deploy/jungle-prod/bootstrap-build-host.sh
bash bootstrap-build-host.sh
```

This installs multi-user nix 2.24.10 (tarball checked against its published
SHA-256) with `nix-command flakes`, clones the repo over https to
`/srv/scuttle/src`, and creates the deploy key
`~/.ssh/id_ed25519_scuttle_deploy`. It does not enable the Cachix cache from
`flake.nix` (`nixConfig` is only honored with `--accept-flake-config`), so
builds use `cache.nixos.org` plus local compilation. A cold build takes tens of
minutes; later ones reuse the store.

Authorize the printed public key on ark-captaind, ark-watchmand and ark-cln
only, restricted to the build host's backend address, in
`~debian/.ssh/authorized_keys`:

```
from="10.42.0.30" ssh-ed25519 AAAA... scuttle-deploy@ark-build
```

The deploy user is `debian` (passwordless sudo): deploy needs root for `/opt`,
`/etc` and `systemctl`. To narrow it, create a `deploy` user with a sudoers
file limited to rsync, mv, ln, systemctl and the setup commands, and set
`DEPLOY_USER`.

## 2. Hosts

```
./setup-host.sh all          # or one role
```

Per host this installs packages (`rsync`, `ca-certificates`; on ark-cln also
`libpq5 libsodium23 libsqlite3-0 tor`), creates the system user, data dir,
`/etc/<service>/` and the systemd unit, and installs the config template only
if the file does not exist yet. A fresh `<file>.dist` copy is always written
next to the config, so you can `diff` after template changes. **Units are
installed, not enabled, not started.**

Tor is installed as a package; its default service is left as Debian sets it
(SOCKS on 127.0.0.1:9050, no hidden service).

On ark-captaind, setup also adds `10.42.0.22 cln hold` to `/etc/hosts`:
cln-grpc's certificate is valid for `cln` and `localhost`, hold's for `hold`
and `localhost`, so captaind addresses them as `https://cln:9736` and
`https://hold:9737`. captaind has no option to set the TLS server name, so the
name must resolve.

Proxmox cloud-init sets `manage_etc_hosts: true`, which rewrites `/etc/hosts`
from `/etc/cloud/templates/hosts.debian.tmpl` on every boot. Setup therefore
adds the entry to that template too; an entry only in `/etc/hosts` disappears
at the next reboot. The template is a conffile, so package upgrades keep it.

Changing a VM's cloud-init settings in Proxmox (SSH keys, password, network)
gives it a new instance ID. On the next boot cloud-init regenerates the SSH
host keys, so `known_hosts` entries for that VM must be replaced.

## 3. First deploy

```
./build.sh scuttle
./deploy.sh latest all
```

## 4. What the human does before starting anything

Secrets are never in the repo. Replace every `CHANGE_ME_...` (units refuse to
start while one remains):

| File (mode 0640 root:service) | Placeholders |
|---|---|
| ark-captaind `/etc/captaind/captaind.toml` | `[postgres]` password, `[bitcoind]` rpc_user/rpc_pass |
| ark-watchmand `/etc/watchmand/watchmand.toml` | `[postgres]` password, `[bitcoind]` rpc_user/rpc_pass |
| ark-cln `/etc/lightning/config` | password in `wallet=` and `hold-database=`, `bitcoin-rpcuser`, `bitcoin-rpcpassword` |

Also review the amounts, fees and round parameters in `captaind.toml`; they are
the upstream defaults apart from the changes listed below.

Start order and key material (all steps create or move secrets, so they are
intentionally not automated):

1. **Postgres.** Create the database and user on the Patroni cluster. The name
   in the templates is `bark-server-db` on host 10.42.0.10.
2. **ark-cln:** `systemctl enable --now lightningd`. The first start creates
   `/var/lib/lightning/bitcoin/hsm_secret`; **back it up immediately**. It also
   generates the plugin certs in `/var/lib/lightning/bitcoin/` (cln-grpc:
   `ca.pem`, `client.pem`, `client-key.pem`) and `.../hold/` (the same names).
   `sudo -u lightning lightning-cli --lightning-dir=/var/lib/lightning getinfo`
   checks it.
3. **Certs to ark-captaind:** copy those six files to
   `/etc/captaind/cln/` and `/etc/captaind/cln/hold/` (owner `root:captaind`,
   mode 0640). The client keys are the credentials for the CLN node.
4. **ark-captaind:** `sudo -u captaind captaind -C /etc/captaind/captaind.toml create`
   creates the database schema and the seed `/var/lib/captaind/mnemonic`. The
   config has `expiry_payouts = true`, which is fixed at database creation, so
   keep that setting when you create the database. Back the mnemonic up.
   Then `systemctl enable --now captaind`.
5. **ark-watchmand** reads the same seed: it has no `create` step and fails to
   start without `/var/lib/watchmand/mnemonic` (the unit checks for it). Place
   the captaind mnemonic there (0600, owner `watchmand`), then
   `systemctl enable --now watchmand`.

The captaind unit sets `CAPTAIND_LOG=info` (the default level, `trace`, is very
verbose and logs user activity; see `contrib/docs/captaind-deployment.md`).


# Settings that differ from the upstream defaults

captaind: `network = "bitcoin"`, `expiry_payouts = true`,
`data_dir = "/var/lib/captaind"`, `otel_deployment_name = "scuttle-mainnet"`,
`rpc.public_address = "10.42.0.20:3535"`, `[[cln_array]]` filled in for ark-cln,
Postgres at the Patroni VIP, bitcoind at 192.168.128.172:8332 with user/pass
auth. Admin stays on loopback (`captaind-deployment.md`).

watchmand: `network = "bitcoin"`, `data_dir = "/var/lib/watchmand"`,
`admin_address = "127.0.0.1:4536"`, same Postgres and bitcoind settings.

lightningd: `network=bitcoin`, `bind-addr=127.0.0.1:9735` (the default
autolisten would bind `0.0.0.0`), `grpc-host`/`hold-grpc-host` on 10.42.0.22,
hold on sqlite in `/var/lib/lightning/hold.sqlite`.

When a release adds config keys, `deploy.sh` stops at the config check. Compare
with `server/captaind.default.toml` or `server/watchmand.default.toml`, edit the
live file on the host, then deploy again. `/etc/<service>/<file>.dist` is the
repo template as last installed by `setup-host.sh`.


# Intentionally left undone

- No service is enabled or started anywhere. No keys, wallets, mnemonics, or
  `hsm_secret` exist; `captaind create` was not run.
- Secrets: bitcoind RPC credentials, Postgres credentials and the CLN certs do
  not exist yet; the config files have placeholders.
- Tor has no hidden service or `announce-addr`; lightningd has no public
  address and no peers or channels. P2P is bound to loopback.
- No public ingress for captaind: the Ark listener is on 10.42.0.20 and waits
  for the tunnel and the rate-limiting TLS proxy.
- CLN's own database is the default sqlite on the VM's disk, and hold uses
  sqlite too. For a node holding mainnet funds decide on backups (or a Postgres
  backend for lightningd) before opening channels.
- Monitoring, log shipping, backups of `/var/lib/*`, and OpenTelemetry are not
  configured.
- The deploy user is the general `debian` sudoer, not a restricted account.
- `captaind`'s amount limits (`max_*_amount`) are unset, as upstream. Decide
  the launch limits before starting.
- The Cachix cache is not used.
