{ system, pkgs, lib, fenix, slog-tools, buildShell, rustTargetWasm,
}:
let
	bitcoinVersion = "30.2";
	lightningVersion = "25.12.1";
	holdPluginVersion = "0.3.3";
	esploraElectrsRevision = "cb1054f689285523617300d4ae97a63965524b7c";
	mempoolElectrsRevision = "v3.3.0";

	isDarwin = pkgs.stdenv.hostPlatform.isDarwin;

	rustToolchain = buildShell.rustToolchain;
	# this toolchain is used to build the internal tools
	rustBuildToolchain = fenix.packages.${system}.combine [
		rustToolchain.rustc
		rustToolchain.cargo
		rustToolchain.rust-src
		rustToolchain.llvm-tools
		rustToolchain.rust-std
	];
	rustPlatform = pkgs.makeRustPlatform {
		cargo = rustBuildToolchain;
		rustc = rustBuildToolchain;
	};

	postgresql = pkgs.postgresql_16;

	bitcoin = pkgs.bitcoind.overrideAttrs (old: {
		version = bitcoinVersion;
		src = pkgs.fetchurl {
			urls = [ "https://bitcoincore.org/bin/bitcoin-core-${bitcoinVersion}/bitcoin-${bitcoinVersion}.tar.gz" ];
			sha256 = "sha256-b9ALjEKIPVyWOQGtQQmjW+Hl7Fwtx2MBjBZsIaBshMs=";
		};
		cmakeFlags = (old.cmakeFlags or []) ++ [
			"-DENABLE_IPC=OFF"
		];
		doCheck = false;
	});

	hal = rustPlatform.buildRustPackage rec {
		pname = "hal";
		version = "0.10.0";
		src = pkgs.fetchCrate {
			inherit pname version;
			sha256 = "sha256-oRmSDQJJu8v7OzsOrFYTyBJcR7wPJtS6hxkta1qEVl0=";
		};
		cargoHash = "sha256-GIcjlICjvu9VKbHlnqQMOqcSeiGLMAN+iF6zaK46Nok=";
	};

	esploraElectrs = rustPlatform.buildRustPackage rec {
		pname = "esplora-electrs";
		version = "99.99.99";
		src = pkgs.fetchFromGitHub {
			owner = "Blockstream";
			repo = "electrs";
			rev = esploraElectrsRevision;
			hash = "sha256-oCzXawzaZRDuOhsUOI1MzgP7VY+aQUlS3F8CgcdtK+I=";
		};

		nativeBuildInputs = [ rustPlatform.bindgenHook ];
		buildInputs = [ pkgs.llvmPackages.clang ];
		doCheck = false;
		cargoLock.lockFile = "${src}/Cargo.lock";
		cargoLock.outputHashes = {
			"electrum-client-0.8.0" = "sha256-HDRdGS7CwWsPXkA1HdurwrVu4lhEx0Ay8vHi08urjZ0=";
			"electrumd-0.1.0" = "sha256-QsoMD2uVDEITuYmYItfP6BJCq7ApoRztOCs7kdeRL9Y=";
			"jsonrpc-0.12.0" = "sha256-lSNkkQttb8LnJej4Vfe7MrjiNPOuJ5A6w5iLstl9O1k=";
		};
	};

	mempoolElectrs = rustPlatform.buildRustPackage rec {
		pname = "mempool-electrs";
		version = "99.99.99";
		src = pkgs.fetchFromGitHub {
			owner = "mempool";
			repo = "electrs";
			rev = mempoolElectrsRevision;
			hash = "sha256-oxeD/z+jCe1dG9tmgYy5AUJKCuX3QNErR5gIARhhoZY=";
		};

		nativeBuildInputs = [ rustPlatform.bindgenHook ];
		buildInputs = [ pkgs.llvmPackages.clang ];
		doCheck = false;
		cargoLock.lockFile = "${src}/Cargo.lock";
		cargoLock.outputHashes = {
			"electrum-client-0.8.0" = "sha256-HDRdGS7CwWsPXkA1HdurwrVu4lhEx0Ay8vHi08urjZ0=";
		};
	};

	clightning = (if isDarwin then null else pkgs.clightning.overrideAttrs (old: {
		version = lightningVersion;
		src = pkgs.fetchurl {
			url = "https://github.com/ElementsProject/lightning/releases/download/v${lightningVersion}/clightning-v${lightningVersion}.zip";
			hash = "sha256-50rcNH9dXeRezJ3nEW/cRK5uE+IpGoHAzkU3C7p44KY=";
		};
		makeFlags = [ "VERSION=v${lightningVersion}" ];
		preInstall = ''
			mkdir -p $out/libexec/c-lightning/plugins/
			touch $out/libexec/c-lightning/plugins/clnrest
		'';
	}));

	cln-grpc = rustPlatform.buildRustPackage rec {
		pname = "cln-grpc";
		version = "99.99.99";
		src = pkgs.fetchFromGitHub {
			owner = "ElementsProject";
			repo = "lightning";
			rev = "v${lightningVersion}";
			hash = "sha256-RgfEEwSqp7qM1CwFFlEUkxjEEAxa3A8kbEuVt4mYJVM=";
		};
		buildAndTestSubdir = "plugins/grpc-plugin";
		nativeBuildInputs = [ rustBuildToolchain pkgs.protobuf ];
		buildInputs = (if isDarwin then [ pkgs.darwin.apple_sdk.frameworks.Security ] else []);
		doCheck = false;
		cargoLock.lockFile = "${src}/Cargo.lock";
		cargoHash = "sha256-UOhoqVs7nxZ98v2lJrAOc/qT8bcSPHekloUObI7wuJc=";
		postUnpack = ''
			rm ${src.name}/configure
		'';
	};

	hold-invoice = rustPlatform.buildRustPackage rec {
		pname = "hold-invoice";
		version = holdPluginVersion;
		src = pkgs.fetchFromGitHub {
			owner = "BoltzExchange";
			repo = "hold";
			rev = "v${holdPluginVersion}";
			hash = "sha256-AIqYN1z91oUfCxM2MALUpduviEzX4mj87GcdFkXnNdQ=";
		};
		nativeBuildInputs = [ rustBuildToolchain pkgs.protobuf ];
		buildInputs = [
			pkgs.sqlite
			postgresql
		] ++ (if isDarwin then [
			pkgs.darwin.apple_sdk.frameworks.Security
		] else []);
		doCheck = false;
		cargoLock.lockFile = "${src}/Cargo.lock";
	};

	cln-plugins = pkgs.linkFarm "plugins" {
		"cln-grpc" = "${cln-grpc}/bin/cln-grpc";
		"hold" = "${hold-invoice}/bin/hold";
	};

	env = buildShell.env // {
		POSTGRES_BINS = "${postgresql}/bin";
		BITCOIND_EXEC = "${bitcoin}/bin/bitcoind";
		ESPLORA_ELECTRS_EXEC = "${esploraElectrs}/bin/electrs";
		MEMPOOL_ELECTRS_EXEC = "${mempoolElectrs}/bin/electrs";
		LIGHTNINGD_EXEC = if isDarwin then null else "${clightning}/bin/lightningd";
		LIGHTNINGD_DOCKER_IMAGE = if isDarwin then "docker.io/secondark/cln-hold:v${lightningVersion}" else null;
		LIGHTNINGD_PLUGIN_DIR = if isDarwin then "/plugins" else "${cln-plugins}";
	};

in {
	inherit env;

	shell = pkgs.mkShell (env // {
		# extend our build shell
		inputsFrom = [ buildShell.shell ];

		packages = [
			(fenix.packages.${system}.combine [
				rustToolchain.rustc
				rustToolchain.cargo
				rustToolchain.rust-src
				rustToolchain.llvm-tools
				rustToolchain.rust-std
				rustToolchain.rust-analyzer
				rustTargetWasm
			])

			slog-tools

			# for bark
			pkgs.sqlite

			# for development
			hal
			pkgs.jq

			# for all tests
			pkgs.cargo-nextest

			# for integration tests
			postgresql
			bitcoin
			clightning
			pkgs.python3 # for clightning
			esploraElectrs
			mempoolElectrs

			# For CI images
			pkgs.coreutils
			pkgs.which
			pkgs.git
			pkgs.gnugrep

			# for rust-bitcoinkernel build
			pkgs.cmake
			pkgs.boost.dev

			# for WASM development
			pkgs.wasm-pack

		] ++ (
			if isDarwin then [
				pkgs.docker
			] else [
				# doesn't work on darwin
				pkgs.cargo-llvm-cov
			]
		);

	});
}
