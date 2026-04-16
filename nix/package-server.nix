{
	craneLib, pkgs, lib,
	gitHash ? "unknown",
	targets ? [ "x86_64-unknown-linux-gnu" ],
}:

let
	crateInfo = craneLib.crateNameFromCargoToml {
		cargoToml = ./../server/Cargo.toml;
	};

	src = lib.fileset.toSource {
		root = ./..;
		fileset = lib.fileset.unions [
			(craneLib.fileset.commonCargoSources ./..)
			./../server-rpc/protos
			./../cln-rpc/protos
			# embed_migrations! reads these SQL files at compile time.
			./../server/src/database/migrations
		];
	};

	cargoVendorDir = craneLib.vendorCargoDeps { inherit src; };

	commonSettings = {
		pname = "bark-server";
		version = crateInfo.version;

		inherit src cargoVendorDir;
		strictDeps = true;
		doCheck = false;

		# Strip via rustc instead of the stdenv fixup phase: the host GNU strip
		# only understands ELF, so a Mach-O or PE artifact would ship unstripped
		# while the Linux ones get stripped. Letting rustc do it works uniformly
		# for every target.
		dontStrip = true;
		CARGO_PROFILE_RELEASE_STRIP = "symbols";

		nativeBuildInputs = with pkgs; [
			pkg-config
			protobuf
			llvmPackages.clang-unwrapped
		];

		GIT_HASH = gitHash;
		BARK_VERSION = crateInfo.version;
		LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
	};

	# The glibc floor for the gnu target. Zig links against glibc version
	# stubs, so the binary uses the standard /lib64 dynamic linker and runs on
	# any distro shipping at least this glibc (2.17 is the manylinux2014 /
	# RHEL7-era baseline), rather than being tied to the nix store like a
	# nixpkgs-linked build would be.
	glibcVersion = "2.17";

	# Zig uses its own target format rather than Rust/clang triples.
	zigTargetMap = {
		"x86_64-unknown-linux-gnu"  = "x86_64-linux-gnu.${glibcVersion}";
		"x86_64-unknown-linux-musl" = "x86_64-linux-musl";
	};

	# cargo-zigbuild understands a glibc version suffix on gnu rust triples.
	zigbuildTarget = target:
		if lib.hasSuffix "-linux-gnu" target then "${target}.${glibcVersion}" else target;

	# Wrapper so cc-rs can cross-compile C code for the zig-based targets. Strips
	# --target=<clang-triple> that cc-rs injects since zig can't parse that format;
	# our own -target flag already sets the target.
	makeZigCC = zigTarget: pkgs.writeShellScript "cc-${zigTarget}" ''
		args=()
		for arg in "$@"; do
			[[ "$arg" == --target=* ]] && continue
			args+=("$arg")
		done
		exec ${pkgs.zig}/bin/zig cc -target ${zigTarget} "''${args[@]}"
	'';

	# Derive env var names from the target triple.
	underscored  = target: builtins.replaceStrings ["-"] ["_"] target;
	ccVar        = target: "CC_${underscored target}";
	rustFlagsVar = target: "CARGO_TARGET_${lib.strings.toUpper (underscored target)}_RUSTFLAGS";

	# Builds the whole bark-server crate so both the captaind and watchmand
	# binaries end up in bin/.
	mkTarget = target:
		craneLib.buildPackage (commonSettings
			// {
				nativeBuildInputs = commonSettings.nativeBuildInputs ++ (with pkgs; [
					zig
					cargo-zigbuild
				]);
				"${ccVar target}"  = "${makeZigCC zigTargetMap.${target}}";
				CARGO_BUILD_TARGET = target;
				preBuild = ''
					export XDG_CACHE_HOME=$TMPDIR/xdg_cache
					mkdir -p $XDG_CACHE_HOME
					export CARGO_ZIGBUILD_CACHE_DIR=$TMPDIR/cargo-zigbuild-cache
					mkdir -p $CARGO_ZIGBUILD_CACHE_DIR
					# cargo hands rustc absolute source paths, so the sandbox build
					# directory lands in the panic location strings that #[track_caller]
					# and file!() leave in .rodata. Those survive the symbol strip, and
					# the directory differs between builders (and, on Determinate Nix,
					# between runs on one builder: /nix/var/nix/builds/nix-<pid>-<rand>).
					# Remap it so the recorded paths are builder-independent.
					export ${rustFlagsVar target}="''${${rustFlagsVar target}:-} --remap-path-prefix=$PWD=/build"
				'';
				buildPhaseCargoCommand = ''
					cargoBuildLog=$(mktemp cargoBuildLogXXXX.json)
					cargo zigbuild --release --locked -p bark-server --target ${zigbuildTarget target} \
						--message-format json-render-diagnostics >"$cargoBuildLog"
				'';
			}
		);

in lib.genAttrs targets mkTarget
