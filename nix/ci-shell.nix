{ pkgs, devShell }:
let
	env = devShell.env // {
		# Ensure cargo actually uses sccache when invoked from within this
		# shell. Kept out of the default shell so local devs aren't
		# implicitly opted in.
		RUSTC_WRAPPER = "sccache";
		# sccache direct mode: hashes preprocessed input rather than
		# running the full preprocessor twice. Big win on non-proc-macro
		# crates; harmless on those that can't use it.
		SCCACHE_DIRECT = "true";
		# Cargo build behavior — pinned so `nix develop` env inheritance
		# quirks can't silently disable them.
		CARGO_INCREMENTAL = "0";
		# Normalize source paths in rustc metadata so a target/ dir built
		# in the base image (/home/nixuser/bark) is fingerprint-compatible
		# with what CI compiles under /builds/ark-bitcoin/bark. MUST match
		# the values in .gitlab-ci.yml and .gitlab/images/tests/Dockerfile
		# byte-for-byte, including flag order.
		CARGO_BUILD_RUSTFLAGS = "--remap-path-prefix=/builds/ark-bitcoin/bark=/build --remap-path-prefix=/home/nixuser/bark=/build";
		# Pinned inside the shell so build scripts run under `nix develop`
		# see it deterministically. The base image writes the zip at this
		# path (Dockerfile line 76), so referencing it here (rather than
		# hoping the CI-side env leaks in through nix develop) keeps the
		# utoipa-swagger-ui build.rs happy.
		SWAGGER_UI_DOWNLOAD_URL = "file:///home/nixuser/assets/swagger-ui/v5.30.2.zip";
		# Show panic messages and backtraces on build.rs failures so we
		# get the `thread 'main' panicked at '…'` line above the stack
		# trace instead of just the trace.
		RUST_BACKTRACE = "full";
	};
in {
	inherit env;

	shell = pkgs.mkShell (env // {
		# Reuse all packages and env from the dev shell; we only layer on
		# CI-specific env vars.
		inputsFrom = [ devShell.shell ];
	});
}
