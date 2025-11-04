# Extra information

## docker-compose.yml
This is a docker compose file that includes bitcoin-core, core-lightning, captaind and bark.
It has a default configuration for regtest.

## cln.Dockerfile + cln_start.sh
These files are also used to create images `docker.io/secondark/cln-hold`.
It's based on `docker.io/elementsproject/lightningd` and adds the [hold](https://github.com/BoltzExchange/hold.git) plugin.
