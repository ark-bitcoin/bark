# captaind deployment: network exposure, DoS protection, and logs

This document is for operators who run captaind. It explains which network
interfaces captaind exposes, what protection captaind itself provides, what
protection your deployment must provide, and how to handle the captaind logs.

## Design: captaind does not rate-limit

captaind does not implement rate limiting, per-IP throttling, connection
caps, or authentication on its public gRPC API. This is a deliberate design
decision, not a missing feature:

- Dedicated edge proxies (Envoy, HAProxy, nginx, Traefik) implement these
  controls better than an application can. They see the real client address,
  they share limits across replicas, and operators already monitor them.
- A server-side equivalent would duplicate configuration that the operator
  already owns at the edge. Two configurations for the same control drift
  apart and give a false sense of safety.
- captaind stays focused on protocol logic. Protocol-level abuse is handled
  in captaind (see [application-level protections](#application-level-protections));
  network-level abuse is handled in front of it.

The consequence: **you must never expose a captaind listen socket directly to
the internet.** A reverse proxy must sit in front of the public API, and the
other APIs must stay on a trusted network.

## The gRPC listeners

captaind binds up to three gRPC listeners, configured in the `[rpc]` section
of the config file:

| Listener | Config key | Trust model |
|----------|------------|-------------|
| Public Ark API | `rpc.public_address` | Serves untrusted clients. Expose only through a rate-limited reverse proxy. |
| Admin API | `rpc.admin_address` | No authentication or transport encryption, by design. As privileged as shell access to the host. Keep it on loopback, or do not start it. |
| Integration API | `rpc.integration_address` | Serves trusted integration services. Make it reachable only on a private network. |

## Requirements for the public API

The reverse proxy in front of `rpc.public_address` must:

- terminate TLS
- enforce per-IP rate limits
- limit the maximum request size
- cap concurrent connections and streams per client

Envoy supports gRPC natively and can apply per-route rate limits with its
local rate limit filter, which makes it a good fit. Any proxy with
equivalent gRPC support works.

When you tune per-method limits, give the strictest limits to the most
expensive methods.

CPU-expensive methods:

- `RecoverVtxosByXpub` costs one EC multiplication per derived key
  (`recovery_xpub_nb_keys` keys per call) plus a database scan. captaind
  also caps concurrent scans with `max_concurrent_xpub_recoveries`.
- The cosign methods (`RequestBoardCosign`, `RequestArkoorCosign`,
  `RequestLeafVtxoCosign`, ...) perform signing operations and database
  writes.
- `SubscribeRounds` holds a long-lived stream per subscriber.

Storage-growth methods. These methods let an unauthenticated caller create
rows in the database (and state on the Lightning node) at no cost. Without
rate limits, a caller can fill the disk:

- `StartLightningReceive` creates a hold invoice on the Lightning node and
  an HTLC subscription row in the database for every unique payment hash.
  The invoice expires after at most `invoice_expiry` (default 48 hours), but the
  caller can submit new payment hashes as fast as the proxy allows. Give
  this method a strict rate limit. Set `max_ln_receive_amount = 0` to
  disable it if you do not offer lightning receives.
- `PostRecoveryVtxoIds` stores up to the per-call maximum of VTXO ids in
  any mailbox. The ids are not validated against known VTXOs, and the
  mailbox authorization is currently optional for backward compatibility.
  Give this method a strict rate limit.
- `PostArkoorMessage` stores VTXOs in a mailbox. captaind only accepts
  VTXOs it cosigned itself and deduplicates repeated posts, so growth is
  bounded by the caller's real VTXOs, but a rate limit still applies.

Methods that register data, such as `RegisterBoardVtxo` and
`RegisterVtxoTransactions`, require a server-cosigned VTXO or an on-chain
funding transaction. They are not free to the caller, but they also deserve
rate limits.

## Requirements for the admin API

The admin API (`rpc.admin_address`) deliberately has no authentication,
authorization, or transport encryption. Anyone who can reach it can manage
the server's wallet and operations. Treat access to this port exactly like
shell access to the host:

- Bind it to loopback only, or comment it out so it does not start.
- Never forward it through a proxy or load balancer.
- For remote administration, use an SSH tunnel or a VPN.

The daemon does not protect this port. Your deployment does.

## Requirements for the integration API

The integration API (`rpc.integration_address`) is for trusted integration
services:

- Make it reachable only on a private network. Firewall the port.
- The integration API trusts the `X-Forwarded-For` header to identify
  clients. Only proxies that sanitize this header may be able to reach it.

## Application-level protections

captaind does implement protections for resources that a network proxy
cannot see. These limits live in the captaind config:

- Amount limits: `max_vtxo_amount`, `max_board_amount`,
  `max_offboard_amount`, `max_arkoor_amount`, `max_round_amount`,
  `max_ln_receive_amount`, `max_ln_send_amount`. Setting a limit to zero
  disables the operation.
- `recovery_xpub_nb_keys` and `max_concurrent_xpub_recoveries` cap the cost
  of xpub recovery scans. Zero disables the RPC.
- `max_read_mailbox_items` caps the size of mailbox query responses.
- `ln_receive_anti_dos_required` requires a VTXO ownership proof or a
  lightning receive token before the server prepares a lightning claim.
- `round_submit_time`, `round_sign_time`, and
  `round_forfeit_nonces_timeout` bound how long a round participant can
  stall a round.
- `offboard_session_timeout` releases VTXOs locked by abandoned offboard
  sessions.

These limits protect protocol and database resources. They do not replace
the edge proxy.

## Logs

We recommend that you keep the captaind logs private.

### What the logs contain

captaind logs the activity of its users. The logs contain:

- VTXO ids and the state of the VTXOs
- unlock hashes of round participations
- payment hashes and Lightning invoices
- public keys of users
- the `user_agent` and the protocol version of each client

The captaind logger adds a timestamp to every line. A reader of the logs
can see when a VTXO was registered, locked, or spent. A reader can also
link a VTXO to a round and to a payment.

The default log level is `trace`. This level produces the most VTXO and
unlock hash lines. Set the `CAPTAIND_LOG` environment variable to a less
verbose level, for example `info`, if you do not need the detail.

### Recommendations for the logs

- Do not publish the logs. Do not post them in public issue trackers or
  chat channels. Remove VTXO ids, unlock hashes, payment hashes, Lightning
  invoices, and public keys before you share an excerpt.
- Restrict read access to the logs to the operators who need it.
- Apply the same recommendations to every copy of the logs. This includes
  log shippers, log aggregators, and backups.
- If you set `otel_collector_endpoint`, captaind also sends span attributes
  and span events to the collector. They include payment hashes, invoices,
  and public keys. Protect the collector in the same way.

### What the logs never contain

captaind must never log a secret that can cause a loss of bitcoin for the
operator. These secrets are:

- private keys
- secret nonces
- the seed phrase

A log line that contains one of these secrets is a vulnerability. See
[SECURITY.md](../../SECURITY.md).

Signatures and public nonces are not secret. They can appear in the logs.

## For security researchers

Reports that state that captaind lacks rate limiting, or that the admin API
lacks authentication, describe the documented design decisions above. They
are not vulnerabilities in captaind. Reports that state that the logs
contain VTXO ids, VTXO states, VTXO policies, unlock hashes, transaction
ids, or UTXOs also describe a documented design decision. See the scope section in
[SECURITY.md](../../SECURITY.md) before you report.

A resource-exhaustion issue can still be in scope: for example, a single
request that costs the server disproportionate resources, or an attack that
works through a correctly configured proxy. A log line that contains a
private key, a secret nonce, or the seed phrase is also in scope. Such
reports are welcome at
[`security@second.tech`](mailto:security@second.tech).
