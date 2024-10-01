{
	description = "ark";

	inputs = {
		nixpkgs.url = "nixpkgs/nixos-24.05";
		flake-utils.url = "github:numtide/flake-utils";
	};

	outputs = { self, nixpkgs, flake-utils }:
		flake-utils.lib.eachDefaultSystem (system:
			let
				lib = nixpkgs.lib;
				pkgs = nixpkgs.legacyPackages.${system};

				target = pkgs.stdenv.buildPlatform.config;
				target_underscores = lib.strings.replaceStrings [ "-" ] [ "_" ] target;
				target_underscores_upper = lib.strings.toUpper target_underscores;

				protobuf = pkgs.protobuf3_23;

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
					buildInputs = [ clang ] ++ (with pkgs; [
						pkg-config
						openssl
					]);

					LLVM_CONFIG_PATH = "${llvmConfigPkg}/bin/llvm-config";
					LLVM_CONFIG_PATH_native = "${llvmConfigPkg}/bin/llvm-config";
					"LLVM_CONFIG_PATH_${target_underscores}" = "${llvmConfigPkg}/bin/llvm-config";
					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
					"CARGO_TARGET_${target_underscores_upper}_LINKER" = "${clang}/bin/clang";

					PROTOC = "${protobuf}/bin/protoc";

					#ROCKSDB_STATIC = "true"; # NB do this for prod
					ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib/";
					#"ROCKSDB_${target_underscores}_STATIC" = "true"; # NB do this for prod
					"ROCKSDB_${target_underscores}_LIB_DIR" = "${pkgs.rocksdb}/lib/";
				};
			}
		);
}
