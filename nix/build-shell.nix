{ pkgs, lib, rustToolchain }:
let
	isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
	postgresql = pkgs.postgresql_17;

	# Pin the generator version: a different version churns all the generated
	# bark-rest-client files and template changes have broken the generator
	# flags in the justfile before (7.17 -> 7.22 renamed the reqwest rustls
	# feature). On a nixpkgs bump, regenerate the client, fix up the justfile
	# flags if needed, and bump this pin together with that commit.
	openapiGeneratorCli =
		assert lib.assertMsg (pkgs.openapi-generator-cli.version == "7.22.0")
			("openapi-generator-cli is ${pkgs.openapi-generator-cli.version}, "
				+ "expected 7.22.0; regenerate bark-rest-client and bump this pin");
		pkgs.openapi-generator-cli;

	env = {
		LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
		CC = "${pkgs.stdenv.cc}/bin/cc";
		CXX = "${pkgs.stdenv.cc}/bin/c++";
		AR = "${pkgs.stdenv.cc}/bin/ar";
		RANLIB = "${pkgs.stdenv.cc}/bin/ranlib";
		LD_LIBRARY_PATH = lib.makeLibraryPath [
			pkgs.gcc.cc.lib
			pkgs.openssl.out
			# hold plugin needs these at runtime
			pkgs.sqlite
			postgresql.lib
		];
		RUST_SRC_PATH = "${rustToolchain.rust-src}/lib/rustlib/src/rust/library";
		RUSTDOCS_STDLIB = "${rustToolchain.rust-docs}/share/doc/rust/html/std/index.html";
	};
in {
	inherit env rustToolchain;

	shell = pkgs.mkShell (env // {
		packages = [
			# Rust
			rustToolchain.rustc
			rustToolchain.cargo
			rustToolchain.clippy
			rustToolchain.rust-src
			rustToolchain.llvm-tools
			rustToolchain.rust-std
			rustToolchain.rust-docs

			# For building
			pkgs.glibcLocales
			pkgs.stdenv.cc
			pkgs.llvmPackages.clang
			pkgs.llvmPackages.bintools
			pkgs.llvmPackages.llvm
			pkgs.pkg-config
			pkgs.gcc.cc.lib
			pkgs.openssl
			pkgs.protobuf

			# For generating clients
			openapiGeneratorCli

			# for bark
			pkgs.sqlite

			# to access just targets
			pkgs.just
			# the justfile locates the cargo target dir with jq
			pkgs.jq

			# CI sets RUSTC_WRAPPER=sccache; shadow the host sccache with the
			# nix one. The host binary picks up this shell's nix openssl via
			# LD_LIBRARY_PATH, whose runtime closure (glibc) conflicts with the
			# host libc it was linked against.
			pkgs.sccache
		] ++ lib.optionals (!isDarwin) [ # honggfuzz deps (Linux only)
			pkgs.binutils-unwrapped
			pkgs.libunwind
			# nixpkgs only installs the shared library, but honggfuzz links
			# BlocksRuntime statically (-Wl,-Bstatic -lBlocksRuntime). Override
			# the install phase to keep libBlocksRuntime.a as well.
			(pkgs.libblocksruntime.overrideAttrs (_: {
				installPhase = ''
					runHook preInstall
					prefix="/" DESTDIR=$out ./installlib
					runHook postInstall
				'';
			}))
			pkgs.xz
			pkgs.gdb
		];
	});
}
