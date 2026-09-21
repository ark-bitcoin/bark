
Building bark
=========


This project has two binary components, each with multiple binaries:

- the Bark server
  - directory: `server/`
  - crate: `bark-server`
  - binaries:
    - `captaind`: principal bark server binary, runs all user-facing
      functionality
    - `watchmand`: watcher daemon without user interaction that watches the
      bitcoin blockchain for relevant events and performs necessary actions

- the Bark CLIs
  - directory: `bark-cli/`
  - crate: `bark-cli`
  - binaries:
    - `barkd`: a production daemon process that runs a Bark wallet and exposes a
      REST API and web UI
    - `bark`: CLI wallet, mostly intended for development use. Plan is to turn this
      into an RPC client to `barkd`.


# Building using cargo

Both binary crates can be built using cargo using the regular cargo build
commands.

The cargo build automatically detects whether it's being built on a release
branch and adapts the version it will show. The git hash is also included.


# Building using Nix (releases, reproducible)

Both binary crates can also be built using nix. The nix build is our release
build pipeline.

Our repo has a flake that exposes targets for all our supported systems. They
are reproducible and intended to be built on Linux (binaries won't reproduce
when built elsewhere).

```
# build using nix directly
$ nix build .#bark
$ ./result/bin/bark --help

# or build all artefacts
$ just nix-build-all
$ ls -l build/
```


# Building barkd with bark-web web UI

`barkd` can be built with a built-in web UI:
[bark-web](https://gitlab.com/ark-bitcoin/bark-web).

There are two ways to affect the bark-web distribution shipped inside `barkd`:
- Builds with either cargo or Nix can set `BARK_WEB_DIST` to a directory that contains a built
  bark-web distribution.
- When building with Nix, you can alternatively set `BARK_WEB_VERSION` to any
  git ref (branch, tag or commit hash) of the bark-web repository and it will
  automatically prepare the dist folder and set `BARK_WEB_DIST` during the build.

We have a just shorthand for this:
```
# build with bark-web's main branch dist
$ just nix-build-bark-web-version main
```
