{
	description = "ark";

	inputs = {
		nixpkgs.url = "nixpkgs/nixos-24.05";
		flake-utils = {
			url = "github:numtide/flake-utils";
		};
		rust-overlay = {
			url = "github:oxalica/rust-overlay";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = { self, nixpkgs, flake-utils, rust-overlay }:
		flake-utils.lib.eachDefaultSystem (system:
			let
				rustVersion = "1.84.0";
				bitcoinVersion = "28.0";
				lightningVersion = "24.08.2";
				protobufVersion = "3.12.4";
				electrsRevision = "9a4175d68ff8a098a05676e774c46aba0c9e558d";

				lib = nixpkgs.lib;
				isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
				overlays = [ rust-overlay.overlays.default ];
				target = lib.strings.replaceStrings [ "-" ] [ "_" ] pkgs.stdenv.buildPlatform.config;
				pkgs = import nixpkgs {
					inherit system overlays;
				};

				rust = pkgs.rust-bin.stable.${rustVersion}.default.override {
					extensions = [ "rust-src" "rust-analyzer" ];
				};

				bitcoin = pkgs.bitcoind.overrideAttrs (old: {
					version = bitcoinVersion;
					src = pkgs.fetchurl {
						urls = [ "https://bitcoincore.org/bin/bitcoin-core-${bitcoinVersion}/bitcoin-${bitcoinVersion}.tar.gz" ];
						sha256 = "sha256-cAri0eIEYC6wfyd5puZmmJO8lsDcopBZP4D/jhAv838=";
					};
					doCheck = false;
				});

				electrs = pkgs.rustPlatform.buildRustPackage rec {
					pname = "esplora-electrs";
					version = "99.99.99";
					src = pkgs.fetchFromGitHub {
						owner = "stevenroose";
						repo = "electrs";
						rev = electrsRevision;
						hash = "sha256-3/0dl+HhUQdCX66ALj+gMndhQAx3AoPJMCqQyq/PK+g=";
					};

					ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib/";
					"ROCKSDB_${target}_LIB_DIR" = "${pkgs.rocksdb}/lib/";
					nativeBuildInputs = [ pkgs.rustPlatform.bindgenHook ];
					buildInputs = [
						pkgs.llvmPackages.clang
					];
					doCheck = false;
					cargoLock.lockFile = "${src}/Cargo.lock";
					cargoLock.outputHashes = {
						"electrum-client-0.8.0" = "sha256-HDRdGS7CwWsPXkA1HdurwrVu4lhEx0Ay8vHi08urjZ0=";
						"electrumd-0.1.0" = "sha256-QsoMD2uVDEITuYmYItfP6BJCq7ApoRztOCs7kdeRL9Y=";
						"jsonrpc-0.12.0" = "sha256-lSNkkQttb8LnJej4Vfe7MrjiNPOuJ5A6w5iLstl9O1k=";
					};
				};

				clightning = (if isDarwin then null else pkgs.clightning.overrideAttrs (old: {
					version = lightningVersion;
					src = pkgs.fetchurl {
						url = "https://github.com/ElementsProject/lightning/releases/download/v${lightningVersion}/clightning-v${lightningVersion}.zip";
						hash = "sha256-U54HNOreulhvCYeULyBbl/WHQ7F9WQnSCSMGg5WUAdg=";
					};
				}));
				cln-grpc = pkgs.rustPlatform.buildRustPackage rec {
					pname = "cln-grpc";
					version = "99.99.99";
					src = pkgs.fetchFromGitHub {
						owner = "ElementsProject";
						repo = "lightning";
						rev = "v${lightningVersion}";
						hash = "sha256-MWU75e55Zt/P4aaIuMte7iRcrFGMw0P81b8VNHQBe2g=";
					};
					buildAndTestSubdir = "plugins/grpc-plugin";
					nativeBuildInputs = [ protobuf ];
					buildInputs = (if isDarwin then [ pkgs.darwin.apple_sdk.frameworks.Security ] else []);
					cargoDeps = pkgs.rustPlatform.importCargoLock {
						lockFile = "${src}/Cargo.lock";
					};
					cargoHash = "sha256-6s1NtTx9LnRXaPVHosKRlU7NMeAHKC/EalRtS+bZXkU=";
					# Avoid doing the configure step of the clightning C project
					postUnpack = ''
						rm ${src.name}/configure
					'';
					doCheck = false; # tests are broken
				};

				protobuf = pkgs.protobuf3_20.overrideAttrs (old: {
					version = protobufVersion;
					src = pkgs.fetchFromGitHub {
						owner = "protocolbuffers";
						repo = "protobuf";
						rev = "v{protobufVersion}";
						hash = "sha256-VyzFq1agobjvei4o/fQ8iMOLySf38DQsLb3C8kCz+78=";
					};
				});
			in
			{
				devShells.default = pkgs.mkShell {
					nativeBuildInput = [ ];
					buildInputs = [
						# For CI image
						pkgs.coreutils
						pkgs.which
						pkgs.git
						pkgs.gnugrep
						# For building
						pkgs.llvmPackages.clang
						pkgs.rustPlatform.bindgenHook
						rust
						pkgs.pkg-config
						protobuf
						pkgs.sqlite
						# For development & testing
						pkgs.just
						pkgs.jq
						pkgs.python3 # for clightning
						bitcoin
						clightning
						electrs
						pkgs.glibcLocales
						pkgs.postgresql
					] ++ (if isDarwin then [
						pkgs.darwin.apple_sdk.frameworks.Security
						pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
						pkgs.docker
					] else []);

					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";

					BITCOIND_EXEC = "${bitcoin}/bin/bitcoind";
					ELECTRS_EXEC = "${electrs}/bin/electrs";

					# Use Docker for Core Lightning on macOS by default instead of a local daemon
					LIGHTNINGD_EXEC = (if isDarwin then null else "${clightning}/bin/lightningd");
					LIGHTNINGD_DOCKER_IMAGE = (if isDarwin then "elementsproject/lightningd:v${lightningVersion}" else null);
					LIGHTNINGD_PLUGINS = "${cln-grpc}/bin/";

					POSTGRES_BINS = "${pkgs.postgresql}/bin";
				};
			}
		);
}
