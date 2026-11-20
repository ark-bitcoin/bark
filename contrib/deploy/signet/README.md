# Private signet deployment

One Debian 13 VM runs a private custom signet and the whole scuttle stack,
for testing the point of sale and wallets end to end. The test deployment is
`scuttle-signet.tailc408a.ts.net`. To try it without access to the VM, use
`wallets.sh` (see "Trying it" below).

| Service | Unit | Address |
|---|---|---|
| bitcoind 32.1, custom signet | `scuttle-bitcoind` | RPC 127.0.0.1:38332, no peers |
| Block miner, every 10 minutes | `scuttle-miner.timer` | |
| Postgres 17 (`captaind`, `posd`) | `postgresql` | 127.0.0.1:5432 |
| CLN with the hold plugin (the Ark server's node) | `scuttle-cln-internal` | p2p 9735, gRPC 9736, hold 9737 |
| CLN without plugins (an outside payer) | `scuttle-cln-external` | p2p 9745, gRPC 9746 |
| captaind (expiry payouts, route hints, zero fees) | `scuttle-captaind` | gRPC 0.0.0.0:3535 |
| watchmand | `scuttle-watchmand` | |
| Forwarder barkd | `scuttle-barkd` | 127.0.0.1:3000 |
| posd and the terminal PWA | `scuttle-posd` | 127.0.0.1:3080 |
| electrs (Esplora API) | `scuttle-electrs` | 127.0.0.1:3002 |

## The chain

- **The signet challenge is `OP_TRUE` (`51`).** Any block with valid proof of
  work is valid. bitcoind does not listen for peers, so only this VM mines.
- **Blocks come every 10 minutes.** Signet retargets every 2,016 blocks like
  mainnet. Faster blocks would raise the difficulty fourfold every period,
  until a CPU can no longer keep up. At 10 minutes the difficulty stays at
  signet's minimum, and a block takes about a second to mine.
- **Block heights match mainnet.** The Ark settings are in blocks, so the
  production values behave as they would on mainnet. A VTXO lives 4,320
  blocks, which is 30 days.
- **Every block carries a few fee-paying transactions.** Without them,
  bitcoind has no fee history, `estimatesmartfee` returns nothing, and CLN
  refuses to open channels. Both CLN nodes also set `force-feerates=2000`.
- **Mine extra blocks** with `sudo -u scuttle /opt/scuttle/bin/signet-mine N`.
  Many quick blocks raise the difficulty at the next retarget, so mine sparingly.

## Build, set up, fund, check

On the VM, from a checkout of the branch to deploy:

```sh
cd pos/web && npm ci && npm run build && cd ../..   # the PWA posd embeds
CARGO_PROFILE_RELEASE_LTO=thin cargo build -j 3 --release -p bark-server -p bark-cli -p scuttle-pos
./contrib/deploy/signet/setup.sh    # installs binaries, configs and units; safe to rerun
./contrib/deploy/signet/fund.sh     # funds captaind and opens a 2 BTC channel; safe to rerun
./contrib/deploy/signet/smoke.sh    # a Lightning sale and an Ark sale, end to end
./contrib/deploy/signet/public.sh   # Tailscale Funnel: posd, Ark server, Esplora
```

Use `-j 3` and thin LTO. With 16 GB of RAM, a full-LTO release build with
8 jobs runs out of memory.

To update a deployment, rebuild and run `setup.sh` again, then restart the
units it changed (`sudo systemctl restart scuttle-captaind scuttle-posd …`).

## Secrets and data

- **`/etc/scuttle/secrets.env`** holds the generated bitcoind and Postgres
  passwords. It is created once and readable only by root and the `scuttle`
  group.
- **Configs** are in `/etc/scuttle/`. Data is in `/var/lib/scuttle/<service>`,
  owned by the `scuttle` user.
- **Seeds:** the captaind seed is `/var/lib/scuttle/captaind/mnemonic`, and
  watchmand has a copy of it.
- **Smoke test wallets** are in `~/smoke` of the user that ran it.

## Reaching it

The VM is on the tailnet as `scuttle-signet.tailc408a.ts.net`. `public.sh`
publishes three services on the internet with Tailscale Funnel:

| URL | Service |
|---|---|
| https://scuttle-signet.tailc408a.ts.net | posd: terminal PWA, API, Lightning address |
| https://scuttle-signet.tailc408a.ts.net:8443 | the Ark server (captaind gRPC) for wallets |
| https://scuttle-signet.tailc408a.ts.net:10000 | Esplora (electrs) |

A wallet uses `--signet --ark https://…:8443 --esplora https://…:10000`.

- **Ports:** Funnel allows only 443, 8443 and 10000.
- **gRPC on 8443:** gRPC needs HTTP/2 negotiated in TLS (ALPN). Funnel's TLS
  termination does not negotiate it and cannot proxy HTTP/2 to a backend.
  So 8443 is raw TCP to nginx on 127.0.0.1:8444, which serves the node's
  Tailscale certificate and passes gRPC to captaind. A weekly timer
  (`scuttle-renew-cert`) renews the certificate.
- **electrs** imports blocks over RPC (`--jsonrpc-import`). It cannot read
  bitcoind's block files, because a custom signet has its own network magic.
- **Test helpers:** `/dev/` on the posd host, from `devtools.py`, gives
  faucet coins, mines blocks and creates a store's on-chain wallet. Each
  has a cap and a rate limit.

## Trying it

`wallets.sh` runs on your own machine and needs only `bark` (built from this
branch), `curl` and `jq`. It drives a store owner's wallet, a customer's
wallet, the owner API and terminals. Run it with no arguments for the full
command list.

```sh
cargo build -p bark-cli --bin bark
alias sw=./contrib/deploy/signet/wallets.sh
sw create owner; sw create customer
sw faucet customer 0.05; sw board customer
sw register "My Cafe" CRC
sw pair                                # open on a phone, or: sw till-pair <link>
sw sell 6250 "2 coffees"; sw pay customer; sw wait
```

## Known limits

- **The Bull app as it ships cannot use this chain.** It runs upstream bark
  from pub.dev. Its Esplora setting can point here once it runs scuttle.
- **The Lightning network is just these two CLN nodes.**
