{ pkgs, lib, rustToolchain }:
let
	isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
	postgresql = pkgs.postgresql_17;

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
			pkgs.openapi-generator-cli

			# for bark
			pkgs.sqlite

			# to access just targets
			pkgs.just
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
