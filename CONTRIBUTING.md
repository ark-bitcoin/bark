
Contributing to bark
====================


# Dependencies

## Nix (Recommended)

You can use the [Nix](https://nix.dev/install-nix) package manager to prepare a development
environment with all necessary dependencies already packaged. We provide a Nix Flake which is tested
against Linux and macOS. You can use it with one of the following methods in the root directory of
the bark repository:

- Run `nix develop`
  - You may need to use the following flag:
    - `--extra-experimental-features "nix-command flakes"`
- Alternatively, use [direnv](https://github.com/direnv/direnv) to do this automatically:
  - `echo "use flake" > .envrc`

## Manual setup

A good starting point for the dev dependencies for bark and the server is to
look at the [CI Dockerfile](./.woodpecker/images/tests/Dockerfile). The dependencies
for Debian should be listed there.

(Below commands might be outdated, the Dockerfile linked above is the better
reference.)

```shell
$ sudo apt install \
	ca-certificates \
	wget \
	curl \
	git \
	xz-utils \
	build-essential \
	cmake \
	clang
```

And install the Rust toolchain:

```shell
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
$ rustup toolchain install 1.82
```


# Running tests

If you're using the Nix flake then [just](https://github.com/casey/just?tab=readme-ov-file#cross-platform)
will come preinstalled. If you aren't using Nix then you must manually install `just` and ensure
that you have [bitcoind](https://bitcoincore.org/en/download/) and [clightning](https://github.com/ElementsProject/lightning)
with the [hold plugin](https://github.com/BoltzExchange/hold)
in your `PATH` variable, alternatively you can set the following environmental variables:
- `BITCOIND_EXEC`: e.g. `export BITCOIND_EXEC="${PATH_TO_BITCOIND}/bin/bitcoind"`
- `LIGHTNINGD_EXEC`: e.g. `export LIGHTNINGD_EXEC="${PATH_TO_LIGHTNINGD}/bin/lightningd"`
- `HODL_INVOICE_PLUGIN`: e.g. `export HODL_INVOICE_PLUGIN="/hold/target/debug/hold"`

You also have to ensure you have a working postgres installation

## Postgres

There are two options to run the tests.
- test managed host (default)
- external host (CI)

### Test managed host

The test framework will launch a new host for every test.
This approach requires that the postgres-binaries such as `initdb` and
`pg_ctl` are installed on your system.

You should either add the binaries to your path or set the `POSTGRES_BINS` environment
variable to the folder that contains them.

The nix-flake in this repository will ensure all binaries are installed correctly.

### External host

If you are running a postgres database it can be used as well. You
can point the `TEST_POSTGRES_HOST` environment variable to your server.

The testing framework will connect using the following credentials and
create a new database on the host for every test.

```
  dbname: postgres
  host: <TEST_POSTGRES_HOST>
  port: 5432
  user: postgres
  password: postgres
```

## Running the tests

Unit and integration tests are configured in the [justfile](justfile) and can be run using the
following command:

```shell
$ just test
```

### macOS differences

On macOS we use [Docker](https://www.docker.com/) for running Core Lightning. If Docker is not
installed then the lightning tests will fail. If you are not using the Nix Flake then you must set
environmental variable for the Docker image to pull:
- `LIGHTNINGD_DOCKER_IMAGE`: e.g. `export LIGHTNINGD_DOCKER_IMAGE="second/cln-hold:v25.02.2"`

Please also make sure "Host networking" feature is enabled, so that Docker-based lightning node
can connect to a bitcoind outside the container. To do so, please refer to
[Docker Desktop documentation](https://docs.docker.com/engine/network/drivers/host/)

# Static files
## Bark database migrations
CI is dumping the resulting DDL into a file, and it's comparing it with `bark/schema.sql`.
So if you add a database migration you should also update this file.

There is a just command to generate this file `just dump-bark-sql-schema`.

## Server database migrations
Just like for bark, CI is also dumping and comparing the DDL for the server database in file `server/schema.sql`.
So if you add a database migration you should also update this file.

There is an equivalent just command to generate this file `just dump-server-sql-schema`.

## Server default configuration
CI is also dumping and comparing the default configuration parameters for the server using file `server/config.default.toml`.
So whenever you change or add a configuration of the server you should change this file accordingly.

There is a just command to generate this file `just default-server-config`.

# Code hygiene

This might be controversial, but the primary objective of your code is to be
understood by your fellow developers. Running correctly is secondary to that.
The reasoning is that correct, but hard-to-understand code might work, but will
probably not get proper review (we're not all big-brains) and will become hard
to maintain. On the other hand, easy-to-understand code is easy to review and
any bugs you might have made will be caught by your reviewers.

What does this mean in practice:
- Use declarative names: both function and variable names.
- Use comments: explain reasoning of complexer parts in common language.
- Use formatting: the way you format code can significantly influence
  readability, use this as a tool in your advantage.

## Some style guidelines

Yes, this does mean that we don't enforce code formatting and don't try to "have
0 clippy warnings". rustfmt produces notoriously horrendous code that is at
times cringe-inducingly space-inefficient and often hinders readability and
reviewability of code. Blind attempts to remove all clippy warnings has been a
common source of introducing subtle bugs/breaking changes.

However, we do try to maintain some coherence in style on some levels:

- Use tabs for indentation, so that each dev can chose their own indentation
  size.
- Try keep to 100 columns in width; some exceptions make sense:
  - logging statements that are purely prints;
  - some testing code, most notably assert statements and method names.
- Organize imports, preferably order imports alphabetically and group by:
  - stdlib
  - external deps
  - internal deps (our own crates)
  - crate deps (same crate)

Generally as a rule of thumb, you can easily look at similar code to see what
our style is. Things like function signature formatting, `where` blocks,
generics, etc can just be deduced from surrounding code.

We are humans, not robots. We write different code, it's fine. It's ok to
comment on readability/coherence, but avoid being pedantic.


# Commit hygiene

We care about our commit history, both for historic purposes and to aid with reviewing.

- Group changes into commits that make logical sense, smaller is better than
  bigger.
- Use descriptive commit messages:
  - prefix the title line with the subsystem you're changing (bark, server, ci,
  testing, ...);
  - feel free to use the body to add extra information and motivation.
- Try to make all your commits individually compile (pass `just check`), or even
  pass all tests (you can use `git rebase --interactive` to check this
  efficiently).
- Avoid fixup commits, but prefer to squash fixups into the original commits.
  - Reviewers can use `git range-diff` to review the fixups to each individual
    commit this way.


