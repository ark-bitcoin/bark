{ pkgs, masterPkgs, lib, slog-tools, buildShell,
	# this toolchain is used to build the internal tools
	rustBuildToolchain,
}:
let
	bitcoinVersion = "29.1";
	lightningVersion = "25.09.1";
	esploraElectrsRevision = "9a4175d68ff8a098a05676e774c46aba0c9e558d";
	mempoolElectrsRevision = "v3.2.0";

	isDarwin = pkgs.stdenv.hostPlatform.isDarwin;

	rustPlatform = pkgs.makeRustPlatform {
		cargo = rustBuildToolchain;
		rustc = rustBuildToolchain;
	};

	postgresql = pkgs.postgresql_16;

	bitcoin = masterPkgs.bitcoind.overrideAttrs (old: {
		version = bitcoinVersion;
		src = pkgs.fetchurl {
			urls = [ "https://bitcoincore.org/bin/bitcoin-core-${bitcoinVersion}/bitcoin-${bitcoinVersion}.tar.gz" ];
			sha256 = "sha256-Bn9iSuJzsNhaFVT/18CYkjNRpkcgTmcDTfbMHfrPoGs=";
		};
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
			owner = "stevenroose";
			repo = "electrs";
			rev = esploraElectrsRevision;
			hash = "sha256-3/0dl+HhUQdCX66ALj+gMndhQAx3AoPJMCqQyq/PK+g=";
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
			hash = "sha256-3/0dl+HhUQdCX66ALj+gMndhQAx3AoPJMCqQyq/PK+g=";
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

	clightning = (if isDarwin then null else pkgs.clightning.overrideAttrs (old: {
		version = lightningVersion;
		src = pkgs.fetchurl {
			url = "https://github.com/ElementsProject/lightning/releases/download/v${lightningVersion}/clightning-v${lightningVersion}.zip";
			hash = "sha256-maH+SSMunXH43Hl9FFvk5L6n4e06vgsL3T8W3ydy+hQ=";
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
			hash = "sha256-H1baJIYmTbXXkvXXBZ9PiYv/yAtd9bGJ7W9yU5k82Xk=";
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
		version = "99.99.99";
		src = pkgs.fetchFromGitHub {
			owner = "BoltzExchange";
			repo = "hold";
			rev = "1e5dec4b479397d77c813060dd01263d689469bc";
			hash = "sha256-VFohDTItt/8TUN0my4gXs0r+JuJ+e7IyO1ZDVoanyfQ=";
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
			slog-tools

			# for bark
			pkgs.sqlite

			# for development
			hal
			pkgs.jq

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
