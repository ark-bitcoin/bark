# Security Policy

## Scope

captaind delegates network-level protection to the deployment
infrastructure. The following are documented design decisions.

- captaind does not rate-limit its public gRPC API. The reverse proxy in
  front of captaind must implement rate limiting.
- The admin and integration gRPC APIs have no authentication, by design.
  The deployment must keep them reachable only on a trusted network.

See [the captaind deployment guide](contrib/docs/captaind-deployment.md)
for the rationale and for operator guidance.

A resource-exhaustion issue can still be in scope: for example, a single
request that costs the server disproportionate resources, or an attack that
works through a correctly configured proxy.

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
