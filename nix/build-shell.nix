{ pkgs, lib, rustToolchain }:
let
	postgresql = pkgs.postgresql_16;

	env = {
		LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
		LD_LIBRARY_PATH = lib.makeLibraryPath [
			pkgs.gcc.cc.lib
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
			pkgs.llvmPackages.clang
			pkgs.llvmPackages.bintools
			pkgs.llvmPackages.llvm
			pkgs.pkg-config
			pkgs.gcc.cc.lib
			pkgs.protobuf

			# For generating clients
			pkgs.openapi-generator-cli

			# for bark
			pkgs.sqlite

			# to access just targets
			pkgs.just
		];

	});
}
