{
	description = "ark";

	inputs = {
		nixpkgs.url = "nixpkgs/nixos-24.05";
		flake-utils = {
			url = "github:numtide/flake-utils";
			inputs.nixpkgs.follows = "nixpkgs";
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
				protobufVersion = "3.12.4";
				bitcoinVersion = "28.0";
				lightningVersion = "24.05";

				lib = nixpkgs.lib;
				overlays = [ rust-overlay.overlays.default ];
				pkgs = import nixpkgs {
					inherit system overlays;
				};

				bitcoin = pkgs.bitcoin.overrideAttrs (old: {
					version = bitcoinVersion;
					src = pkgs.fetchurl {
						urls = [ "https://bitcoincore.org/bin/bitcoin-core-${bitcoinVersion}/bitcoin-${bitcoinVersion}.tar.gz" ];
						sha256 = "sha256-cAri0eIEYC6wfyd5puZmmJO8lsDcopBZP4D/jhAv838=";
					};
				});

				clightning = pkgs.clightning.overrideAttrs (old: {
					version = lightningVersion;
					src = pkgs.fetchurl {
						url = "https://github.com/ElementsProject/lightning/releases/download/v${lightningVersion}/clightning-v${lightningVersion}.zip";
						hash = "sha256-FD7JFM80wrruqBWjYnJHZh2f2GZJ6XDQmUQ0XetnWBg=";
					};
				});

				protobuf = pkgs.protobuf3_20.overrideAttrs (old: {
					version = protobufVersion;
					src = pkgs.fetchFromGitHub {
						owner = "protocolbuffers";
						repo = "protobuf";
						rev = "v{protobufVersion}";
						hash = "sha256-VyzFq1agobjvei4o/fQ8iMOLySf38DQsLb3C8kCz+78=";
					};
				});

				target = pkgs.stdenv.buildPlatform.config;
				target_underscores = lib.strings.replaceStrings [ "-" ] [ "_" ] target;
				target_underscores_upper = lib.strings.toUpper target_underscores;

				# This is a bunch of stuff that is somehow necessary to build rocksdb.
				targetLlvmConfigWrapper = { binClangPkg, libClangPkg }: pkgs.writeShellScriptBin "llvm-config" ''
					if [ "$1" == "--bindir" ]; then
						echo "${binClangPkg}/bin"
						exit 0
					fi
					if [ "$1" == "--prefix" ]; then
						echo "${libClangPkg}"
						exit 0
					fi
					exec llvm-config "$@"
				'';
				llvmConfigPkg = targetLlvmConfigWrapper {
					binClangPkg = pkgs.llvmPackages.clang;
					libClangPkg = pkgs.llvmPackages.clang-unwrapped.lib;
				};
				clang = pkgs.llvmPackages.clang;
			in
			{
				devShells.default = pkgs.mkShell {
					nativeBuildInput = [ ];
					buildInputs = [ clang ] ++ [
						(pkgs.rust-bin.stable.${rustVersion}.default.override {
							extensions = [ "rust-src" "rust-analyzer" ];
						})
						pkgs.pkg-config
						protobuf
						pkgs.sqlite
						bitcoin
						clightning
					];

					LLVM_CONFIG_PATH = "${llvmConfigPkg}/bin/llvm-config";
					LLVM_CONFIG_PATH_native = "${llvmConfigPkg}/bin/llvm-config";
					"LLVM_CONFIG_PATH_${target_underscores}" = "${llvmConfigPkg}/bin/llvm-config";
					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
					"CARGO_TARGET_${target_underscores_upper}_LINKER" = "${clang}/bin/clang";

					PROTOC = "${protobuf}/bin/protoc";

					ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib/";
					"ROCKSDB_${target_underscores}_LIB_DIR" = "${pkgs.rocksdb}/lib/";
					#ROCKSDB_STATIC = "true"; # NB do this for prod
					#"ROCKSDB_${target_underscores}_STATIC" = "true"; # NB do this for prod
				};
			}
		);
}
