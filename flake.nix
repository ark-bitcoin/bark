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
				rustVersion = "1.77.1";
				bitcoinVersion = "28.0";
				lightningVersion = "24.08.2";
				protobufVersion = "3.12.4";

				lib = nixpkgs.lib;
				isDarwin = builtins.match ".*darwin.*" system != null;
				overlays = [ rust-overlay.overlays.default ];
				pkgs = import nixpkgs {
					inherit system overlays;
				};


				rust = pkgs.rust-bin.stable.${rustVersion}.default.override {
					extensions = [ "rust-src" "rust-analyzer" ];
				};
				bitcoin = pkgs.bitcoin.overrideAttrs (old: {
					version = bitcoinVersion;
					src = pkgs.fetchurl {
						urls = [ "https://bitcoincore.org/bin/bitcoin-core-${bitcoinVersion}/bitcoin-${bitcoinVersion}.tar.gz" ];
						sha256 = "sha256-cAri0eIEYC6wfyd5puZmmJO8lsDcopBZP4D/jhAv838=";
					};
				});

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
						lockFile = ./Cargo.lock;
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

				target = lib.strings.replaceStrings [ "-" ] [ "_" ] pkgs.stdenv.buildPlatform.config;
			in
			{
				devShells.default = pkgs.mkShell {
					nativeBuildInput = [ ];
					buildInputs = [ pkgs.llvmPackages.clang ] ++ [
						# For CI image
						pkgs.coreutils
						pkgs.which
						pkgs.git
						pkgs.gnugrep
						# For building
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
					] ++ (if isDarwin then [
						pkgs.darwin.apple_sdk.frameworks.Security
						pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
					] else []);

					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";

					ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib/";
					"ROCKSDB_${target}_LIB_DIR" = "${pkgs.rocksdb}/lib/";
					#ROCKSDB_STATIC = "true"; # NB do this for prod
					#"ROCKSDB_${target}_STATIC" = "true"; # NB do this for prod

					BITCOIND_EXEC = "${bitcoin}/bin/bitcoind";
					LIGHTNINGD_DOCKER_IMAGE = "elementsproject/lightningd:v${lightningVersion}";
					LIGHTNINGD_EXEC = (if !isDarwin then "${clightning}/bin/lightningd" else null);
					LIGHTNINGD_PLUGINS = "${cln-grpc}/bin/";
				};
			}
		);
}
