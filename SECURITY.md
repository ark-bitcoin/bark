# Security Policy

## Scope

captaind delegates network-level protection to the deployment
infrastructure. The following are documented design decisions.

- captaind does not rate-limit its public gRPC API. The reverse proxy in
  front of captaind must implement rate limiting.
- The admin and integration gRPC APIs have no authentication, by design.
  The deployment must keep them reachable only on a trusted network.
- The captaind logs contain VTXO ids, VTXO states, VTXO policies, unlock
  hashes, transaction ids, and UTXOs. With the timestamps, they can show
  when a VTXO was spent. We recommend that operators keep the logs private.

See [the captaind deployment guide](contrib/docs/captaind-deployment.md)
for the rationale and for operator guidance.

A resource-exhaustion issue can still be in scope: for example, a single
request that costs the server disproportionate resources, or an attack that
works through a correctly configured proxy.

A log line that contains a private key, a secret nonce, or the seed phrase is
in scope. Signatures and public nonces in the logs are not.

### Test, CI, and build code

We consider our CI and test code part of our product and of our security
model. We protect what has value: the CI secrets, the CI runners, and the
code and binaries that we publish. The test harness runs only on regtest,
and only on developer machines and CI runners that have no untrusted users.
Its secrets protect regtest coins and have no value.

These findings are in scope:

- anything that exposes a CI secret
- anything that lets an untrusted party run code on CI. This is why CI does
  not run for external contributors. The pipeline of an external
  contributor runs only after a manual review.
- anything that lets someone publish malicious binaries or code to a package
  registry or to the release page

These findings are out of scope:

- attacks that need another user or process on a developer machine or a CI
  runner. Examples are symlinks planted in `/tmp`, another process that
  binds a test port first, and a program found through `PATH`.
- default passwords, improper access rights, or weak seed phrases in test
  code
- regtest secrets in process arguments, logs, or files
- theft of regtest coins

## Reporting a Vulnerability

Please report any vulnerability or any bug that could potentially affect the
security of users' funds by e-mail to [`security@second.tech`](mailto:security@second.tech).

Please do not report security issues through public issue trackers or chat
channels.

You may use the following PGP keys to encrypt your e-mail:

- `8CC974D9CFD034DCEED213B02A57E0A610D7F19C` (Steven Roose)
- `011E7F59B45397C4654D81298F44B2DD98E18528` (Erik De Smedt)

Both keys can be found on the [keys.openpgp.org](https://keys.openpgp.org/)
keyserver.
