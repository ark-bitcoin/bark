# Extra information

## docker-compose.yml
This is a docker compose file that includes bitcoin-core, core-lightning, captaind and bark.
It has a default configuration for regtest.

## cln.Dockerfile + cln_start.sh
These files are also used to create images `docker.io/secondark/cln-hold`.
It's based on `docker.io/elementsproject/lightningd` and adds the [hold](https://gitlab.com/ark-bitcoin/hold) plugin.

Images are tagged `v<CLN_VERSION>-<short HOLD_PLUGIN_REVISION>`, e.g. `v26.06.10-efc7d5f`.
The nix dev shell derives the tag it uses on macOS from `lightningVersion` and
`holdPluginRevision` in `nix/dev-shell.nix`, so keep those in sync with this Dockerfile.

```sh
docker build -f contrib/docker/cln.Dockerfile -t docker.io/secondark/cln-hold:v26.06.10-efc7d5f .
docker push docker.io/secondark/cln-hold:v26.06.10-efc7d5f
```
