{
	description = "ark";

	# To update a single input, use
	# $ nix flake update --update-input rust-overlay
	#
	inputs = {
		nixpkgs.url = "nixpkgs/nixos-24.11";
		nixpkgs-master.url = "github:NixOS/nixpkgs/master";
		flake-utils.url = "github:numtide/flake-utils";
		rust-overlay = {
			url = "github:oxalica/rust-overlay";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = { self, nixpkgs, nixpkgs-master, flake-utils, rust-overlay }:
		flake-utils.lib.eachDefaultSystem (system:
			let
				rustVersion = "1.88.0";
				bitcoinVersion = "29.0";
				lightningVersion = "25.02.2";
				postgresVersion = "16.9";
				esploraElectrsRevision = "9a4175d68ff8a098a05676e774c46aba0c9e558d";
				mempoolElectrsRevision = "v3.2.0";

				lib = nixpkgs.lib;
				isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
				overlays = [ rust-overlay.overlays.default ];
				target = lib.strings.replaceStrings [ "-" ] [ "_" ] pkgs.stdenv.buildPlatform.config;
				pkgs = import nixpkgs {
					inherit system overlays;
				};

				masterPkgs = import nixpkgs-master {
					inherit system;
				};

				rust = pkgs.rust-bin.stable.${rustVersion}.default.override {
					extensions = [ "rust-src" "rust-analyzer" "llvm-tools-preview" ];
				};

				bitcoin = masterPkgs.bitcoind.overrideAttrs (old: {
					version = bitcoinVersion;
					src = pkgs.fetchurl {
						urls = [ "https://bitcoincore.org/bin/bitcoin-core-${bitcoinVersion}/bitcoin-${bitcoinVersion}.tar.gz" ];
						sha256 = "sha256-iCx4LDSjvy6s0frlzcWLNbhpiDUS8Zf31tyPGV3s/ao=";
					};
					doCheck = false;
				});

				hal = pkgs.rustPlatform.buildRustPackage rec {
					pname = "hal";
					version = "0.10.0";
					src = pkgs.fetchCrate {
						inherit pname version;
						sha256 = "sha256-oRmSDQJJu8v7OzsOrFYTyBJcR7wPJtS6hxkta1qEVl0=";
					};
					cargoHash = "sha256-/YCOI+BxscMAu9RgAt1QnivAnPSydkljgR2zWV84tQE=";
				};

				esploraElectrs = pkgs.rustPlatform.buildRustPackage rec {
					pname = "esplora-electrs";
					version = "99.99.99";
					src = pkgs.fetchFromGitHub {
						owner = "stevenroose";
						repo = "electrs";
						rev = esploraElectrsRevision;
						hash = "sha256-3/0dl+HhUQdCX66ALj+gMndhQAx3AoPJMCqQyq/PK+g=";
					};

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

				mempoolElectrs = pkgs.rustPlatform.buildRustPackage rec {
					pname = "mempool-electrs";
					version = "99.99.99";
					src = pkgs.fetchFromGitHub {
						owner = "mempool";
						repo = "electrs";
						rev = mempoolElectrsRevision;
						hash = "sha256-3/0dl+HhUQdCX66ALj+gMndhQAx3AoPJMCqQyq/PK+g=";
					};

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
						hash = "sha256-2wp9o1paWJWfxIvm9BDnsKX3GDUXKaPkpB89cwb6Oj8=";
					};
					makeFlags = [ "VERSION=v${lightningVersion}" ];
					# some makefile bug: https://github.com/ElementsProject/lightning/issues/8141
					preInstall = ''
					mkdir -p $out/libexec/c-lightning/plugins/
					touch $out/libexec/c-lightning/plugins/clnrest
					'';
				}));
				cln-grpc = pkgs.rustPlatform.buildRustPackage rec {
					pname = "cln-grpc";
					version = "99.99.99";
					src = pkgs.fetchFromGitHub {
						owner = "ElementsProject";
						repo = "lightning";
						rev = "v${lightningVersion}";
						hash = "sha256-SiPYB463l9279+zawsxmql1Ui/dTdah5KgJgmrWsR2A=";
					};
					buildAndTestSubdir = "plugins/grpc-plugin";
					nativeBuildInputs = [ rust pkgs.protobuf ];
					buildInputs = (if isDarwin then [ pkgs.darwin.apple_sdk.frameworks.Security ] else []);
					cargoDeps = pkgs.rustPlatform.importCargoLock {
						lockFile = "${src}/Cargo.lock";
					};
					cargoHash = "sha256-UOhoqVs7nxZ98v2lJrAOc/qT8bcSPHekloUObI7wuJc=";
					# Avoid doing the configure step of the clightning C project
					postUnpack = ''
						rm ${src.name}/configure
					'';
					doCheck = false; # tests are broken
				};
				hold-invoice = pkgs.rustPlatform.buildRustPackage rec {
					pname = "hold-invoice";
					version = "99.99.99";
					src = pkgs.fetchFromGitHub {
						owner = "BoltzExchange";
						repo = "hold";
						rev = "v0.2.2";
						hash = "sha256-vksvnLV9pcMxJcoylF+r2ezQmauiGGt+/MSNMfS3Gxc=";
					};
					nativeBuildInputs = [ rust pkgs.protobuf ];
					buildInputs = [
						pkgs.sqlite
						pkgs.postgresql
					] ++ (if isDarwin then [
						pkgs.darwin.apple_sdk.frameworks.Security
					] else []);
					cargoDeps = pkgs.rustPlatform.importCargoLock {
						lockFile = "${src}/Cargo.lock";
					};
					doCheck = false;
				};
				cln-plugins = pkgs.linkFarm "plugins" {
					"cln-grpc" = "${cln-grpc}/bin/cln-grpc";
					"hold" = "${hold-invoice}/bin/hold";
				};

				postgresql = pkgs.postgresql.overrideAttrs (old: {
					version = "${postgresVersion}";
					src = pkgs.fetchurl {
						url = "https://ftp.postgresql.org/pub/source/v${postgresVersion}/postgresql-${postgresVersion}.tar.bz2";
						hash = "sha256-B8APuCTfCgwpXySfRGkbhuMmZ1OzgMlvYzwzEeEL0AU=";
					};
				});

				slogJq = name: filter: pkgs.writeShellApplication {
					inherit name;
					text = ''
						arg="";
						if [ $# -gt 0 ]; then
							arg=$1
						fi
						# check if we are piping into TTY or not
						if [ -t 1 ]; then
							jq -c --arg arg "$arg" '${filter}' | slf
						else
							jq -c --arg arg "$arg" '${filter}'
						fi
					'';
				};
				slogCommands = [
					(slogJq "slmod"  ''select((.module | split("::") | index($arg)) != null)'')
					(slogJq "slwarn" ''select(.level == "WARN" or .level == "ERROR")'')
					(slogJq "slinfo" ''select(.level == "INFO" or .level == "WARN" or .level == "ERROR")'')
					(pkgs.writeShellApplication {
						name = "slf"; # pretty format
						text = '' exec jq -r '
							# Extract HH:MM:SS.mmm from RFC3339-like timestamps with nanos
							def time_ms3(ts):
								(ts | capture("T(?<h>\\d{2}):(?<m>\\d{2}):(?<s>\\d{2})(?:\\.(?<ms>\\d{3})\\d*)?"))
									| "\(.h):\(.m):\(.s).\(.ms // "000")";

							# Right-pad string s to width n with spaces (no truncate)
							def rpad($n; $s):
								($s // "") as $s0 | ($s0|length) as $L |
									$s0 + (if $L < $n then (reduce range(0; $n - $L) as $_ (""; . + " ")) else "" end);

							"\(time_ms3(.timestamp)) \(rpad(5; .level)) \(rpad(16; .module))  \(
								if .kv != null
									then "\(.kv.slog_id) - \(.message): \(.kv.slog_data)"
									else "\(.message)"
								end
							)"
						';
						'';
					})
				];
			in
			{
				devShells.default = pkgs.mkShell {
					nativeBuildInputs = [ ];
					buildInputs = slogCommands ++ [
						# For CI image
						pkgs.coreutils
						pkgs.which
						pkgs.git
						pkgs.gnugrep
						# For building
						pkgs.llvmPackages_16.clang
						pkgs.llvmPackages_16.bintools
						pkgs.llvmPackages_16.llvm
						pkgs.rustPlatform.bindgenHook
						rust # includes cargo & rust-analyzer
						pkgs.pkg-config
						pkgs.protobuf
						pkgs.sqlite
						# For development & testing
						pkgs.just
						hal
						pkgs.jq
						pkgs.python3 # for clightning
						bitcoin
						clightning
						esploraElectrs
						mempoolElectrs
						pkgs.glibcLocales
						postgresql
					] ++ (if isDarwin then [
						pkgs.darwin.apple_sdk.frameworks.Security
						pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
						pkgs.docker
					] else [
						pkgs.cargo-llvm-cov
					]);

					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";

					BITCOIND_EXEC = "${bitcoin}/bin/bitcoind";
					ESPLORA_ELECTRS_EXEC = "${esploraElectrs}/bin/electrs";
					MEMPOOL_ELECTRS_EXEC = "${mempoolElectrs}/bin/electrs";

					# Use Docker for Core Lightning on macOS by default instead of a local daemon
					LIGHTNINGD_EXEC = (if isDarwin then null else "${clightning}/bin/lightningd");
					LIGHTNINGD_DOCKER_IMAGE = (if isDarwin then "docker.io/secondark/cln-hold:v${lightningVersion}" else null);
					LIGHTNINGD_PLUGIN_DIR = (if isDarwin then "/plugins" else "${cln-plugins}");

					POSTGRES_BINS = "${postgresql}/bin";

					RUSTDOCS_STDLIB = "${rust}/share/doc/rust/html/std/index.html";
				};
			}
		);
}
