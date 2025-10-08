{ pkgs, masterPkgs, lib, rustToolchain, rustBuildToolchain }:
let
	bitcoinVersion = "29.1";
	lightningVersion = "25.09";
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
			hash = "sha256-qX9EZHuDtEcYCU8YOMbHTo3JDAAJ8nc6N7F/+AAEpn4=";
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
			hash = "sha256-SiPYB463l9279+zawsxmql1Ui/dTdah5KgJgmrWsR2A=";
		};
		buildAndTestSubdir = "plugins/grpc-plugin";
		nativeBuildInputs = [ rustBuildToolchain pkgs.protobuf ];
		buildInputs = (if isDarwin then [ pkgs.darwin.apple_sdk.frameworks.Security ] else []);
		cargoDeps = rustPlatform.importCargoLock { lockFile = "${src}/Cargo.lock"; };
		cargoHash = "sha256-UOhoqVs7nxZ98v2lJrAOc/qT8bcSPHekloUObI7wuJc=";
		postUnpack = ''
			rm ${src.name}/configure
		'';
		doCheck = false;
	};

	hold-invoice = rustPlatform.buildRustPackage rec {
		pname = "hold-invoice";
		version = "99.99.99";
		src = pkgs.fetchFromGitHub {
			owner = "BoltzExchange";
			repo = "hold";
			rev = "v0.2.2";
			hash = "sha256-vksvnLV9pcMxJcoylF+r2ezQmauiGGt+/MSNMfS3Gxc=";
		};
		nativeBuildInputs = [ rustBuildToolchain pkgs.protobuf ];
		buildInputs = [
			pkgs.sqlite
			postgresql
		] ++ (if isDarwin then [
			pkgs.darwin.apple_sdk.frameworks.Security
		] else []);
		cargoDeps = rustPlatform.importCargoLock { lockFile = "${src}/Cargo.lock"; };
		doCheck = false;
	};

	cln-plugins = pkgs.linkFarm "plugins" {
		"cln-grpc" = "${cln-grpc}/bin/cln-grpc";
		"hold" = "${hold-invoice}/bin/hold";
	};

	slogJq = name: filter: pkgs.writeShellApplication {
		inherit name;
		text = ''
			arg=""
			if [ $# -gt 0 ]; then
				arg=$1
			fi
			if [ -t 1 ]; then
				jq -c --arg arg "$arg" '${filter}' | slf
			else
				jq -c --arg arg "$arg" '${filter}'
			fi
		'';
	};

	slogCommands = [
		(slogJq "slmod" ''select((.module | split("::") | index($arg)) != null)'')
		(slogJq "sls" ''select(.kv != null)'')
		(slogJq "slwarn" ''select(.level == "WARN" or .level == "ERROR")'')
		(slogJq "slinfo" ''select(.level == "INFO" or .level == "WARN" or .level == "ERROR")'')
		(slogJq "sldebug" ''select(.level == "DEBUG" or .level == "INFO" or .level == "WARN" or .level == "ERROR")'')
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
				"\(time_ms3(.timestamp)) \(rpad(5; .level)) \(rpad(16; .module)) \(
					if .kv != null
					then "\(.kv.slog_id) - \(.message): \(.kv.slog_data)"
					else "\(.message)"
					end
				)"
			';
			'';
		})
	];

in pkgs.mkShell {
	buildInputs = [

		# For building
		rustBuildToolchain
		rustPlatform.bindgenHook
		pkgs.glibcLocales
		pkgs.llvmPackages.clang
		pkgs.llvmPackages.bintools
		pkgs.llvmPackages.llvm
		pkgs.pkg-config
		pkgs.gcc.cc.lib
		pkgs.protobuf

		# for bark
		pkgs.sqlite

		# for development
		rustToolchain.rust-docs
		rustToolchain.rust-analyzer
		hal
		pkgs.jq
		pkgs.just

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

	LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
	RUSTDOCS_STDLIB = "${rustToolchain.rust-docs}/share/doc/rust/html/std/index.html";
	LD_LIBRARY_PATH = lib.makeLibraryPath [
		pkgs.gcc.cc.lib
		# hold plugin needs these at runtime
		pkgs.sqlite
		postgresql.lib
	];

	POSTGRES_BINS = "${postgresql}/bin";
	BITCOIND_EXEC = "${bitcoin}/bin/bitcoind";
	ESPLORA_ELECTRS_EXEC = "${esploraElectrs}/bin/electrs";
	MEMPOOL_ELECTRS_EXEC = "${mempoolElectrs}/bin/electrs";
	LIGHTNINGD_EXEC = if isDarwin then null else "${clightning}/bin/lightningd";
	LIGHTNINGD_DOCKER_IMAGE = if isDarwin then "docker.io/secondark/cln-hold:v${lightningVersion}" else null;
	LIGHTNINGD_PLUGIN_DIR = if isDarwin then "/plugins" else "${cln-plugins}";
}
