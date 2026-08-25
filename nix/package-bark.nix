{
	craneLib, pkgs, lib,
	gitHash ? "unknown",
	targets ? [ "x86_64-unknown-linux-gnu" ],
	# Path to a macOS SDK used when cross-compiling the apple-darwin targets.
	# When null we fall back to the BARK_MACOS_SDK env var (requires --impure)
	# and, failing that, to a redistributable SDK fetched automatically. This
	# lets users without Xcode build out of the box, while users who already
	# have an SDK can point at it instead of downloading one.
	macosSdk ? null,
}:

let
	crateInfo = craneLib.crateNameFromCargoToml {
		cargoToml = ./../bark-cli/Cargo.toml;
	};

	# The version stamped into the binaries. Mirrors bark-cli/build.rs: only
	# a build of the commit carrying the bark-X.Y.Z release tag gets the
	# clean release version, anything else keeps the crate version as a
	# readable base with a -dev suffix. The nix sandbox has no .git to
	# inspect the tag, so release builds pass the version in through the
	# BARK_VERSION env var (visible only under `nix build --impure`); the
	# justfile bark release recipes do this automatically when HEAD carries
	# the tag. In pure evaluation getEnv returns "", i.e. dev.
	envVersion = builtins.getEnv "BARK_VERSION";
	barkVersion = if envVersion != "" then envVersion else "${crateInfo.version}-dev";

	src = lib.fileset.toSource {
		root = ./..;
		fileset = lib.fileset.unions [
			(craneLib.fileset.commonCargoSources ./..)
			./../server-rpc/protos
			./../cln-rpc/protos
		];
	};

	cargoVendorDir = craneLib.vendorCargoDeps { inherit src; };

	commonSettings = {
		pname = "bark";
		version = crateInfo.version;

		inherit src cargoVendorDir;
		strictDeps = true;
		doCheck = false;

		# Strip via rustc instead of the stdenv fixup phase: the host GNU strip
		# only understands ELF, so the Mach-O and PE artifacts would ship
		# unstripped while the Linux ones get stripped. Letting rustc do it
		# works uniformly for every target.
		dontStrip = true;
		CARGO_PROFILE_RELEASE_STRIP = "symbols";

		nativeBuildInputs = with pkgs; [
			pkg-config
			protobuf
			llvmPackages.clang-unwrapped
		];

		GIT_HASH = gitHash;
		BARK_VERSION = barkVersion;
		LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
	};

	# The glibc floor for the gnu targets. Zig links against glibc version
	# stubs, so the binary uses the standard /lib64 dynamic linker and runs on
	# any distro shipping at least this glibc (2.17 is the manylinux2014 /
	# RHEL7-era baseline; debian and ubuntu releases from the last decade all
	# qualify), rather than being tied to the nix store like a nixpkgs-linked
	# build would be.
	glibcVersion = "2.17";

	# Zig uses its own target format rather than Rust/clang triples.
	zigTargetMap = {
		"x86_64-apple-darwin"      = "x86_64-macos.11.0";
		"aarch64-apple-darwin"     = "aarch64-macos.11.0";
		"x86_64-pc-windows-gnu"    = "x86_64-windows-gnu";
		"x86_64-unknown-linux-gnu"   = "x86_64-linux-gnu.${glibcVersion}";
		"x86_64-unknown-linux-musl"  = "x86_64-linux-musl";
		"aarch64-unknown-linux-musl" = "aarch64-linux-musl";
		"armv7-unknown-linux-musleabihf" = "arm-linux-musleabihf";
	};

	# cargo-zigbuild understands a glibc version suffix on gnu rust triples.
	zigbuildTarget = target:
		if isGnuTarget target then "${target}.${glibcVersion}" else target;

	# Wrapper so cc-rs can cross-compile C code (bundled SQLite, secp256k1) for the
	# zig-based targets (macOS, Windows). Strips --target=<clang-triple> that cc-rs
	# injects since zig can't parse that format; our own -target flag already sets
	# the right target.
	makeZigCC = zigTarget: pkgs.writeShellScript "cc-${zigTarget}" ''
		args=()
		for arg in "$@"; do
			[[ "$arg" == --target=* ]] && continue
			args+=("$arg")
		done
		exec ${pkgs.zig}/bin/zig cc -target ${zigTarget} "''${args[@]}"
	'';

	# Cross-compiling to macOS still needs an Apple SDK to link against system
	# frameworks (CoreFoundation, Security, ...) — zig bundles a libc but not the
	# frameworks. We don't require a full Xcode install: resolve the SDK from, in
	# order of precedence, the `macosSdk` argument, the BARK_MACOS_SDK env var
	# (only visible under `nix build --impure`), or a trimmed redistributable SDK
	# fetched from GitHub. The redistributable SDK is a copy of Apple's
	# proprietary SDK; Apple's licence restricts its use to Apple hardware.
	defaultMacosSdk = pkgs.fetchzip {
		url = "https://github.com/joseluisq/macosx-sdks/releases/download/11.3/MacOSX11.3.sdk.tar.xz";
		hash = "sha256-zQjqyMp6GFbsIAU6WCBca793KcrZtSQ5tv/pfETxe5w=";
	};

	envMacosSdk = let v = builtins.getEnv "BARK_MACOS_SDK"; in if v == "" then null else v;

	sdkroot =
		if macosSdk != null then macosSdk
		else if envMacosSdk != null then envMacosSdk
		else defaultMacosSdk;

	isDarwinTarget = target: lib.hasSuffix "apple-darwin" target;
	isWindowsTarget = target: lib.hasSuffix "pc-windows-gnu" target;
	isGnuTarget = target: lib.hasSuffix "-linux-gnu" target;
	# hasInfix rather than hasSuffix so armv7-...-musleabihf matches too.
	isMuslTarget = target: lib.hasInfix "-linux-musl" target;

	# Derive env var names from the target triple.
	underscored   = target: builtins.replaceStrings ["-"] ["_"] target;
	ccVar         = target: "CC_${underscored target}";
	cFlagsVar     = target: "CFLAGS_${underscored target}";
	rustFlagsVar  = target: "CARGO_TARGET_${lib.strings.toUpper (underscored target)}_RUSTFLAGS";

	mkTarget = target:
		let
			isDarwin = isDarwinTarget target;
			isWindows = isWindowsTarget target;
		in craneLib.buildPackage (commonSettings
			// {
				nativeBuildInputs = commonSettings.nativeBuildInputs ++ (with pkgs; [
					zig
					cargo-zigbuild
				])
				# rustc shells out to dlltool to synthesize import libraries for
				# windows-gnu crates that use raw-dylib linking (getrandom, windows-sys);
				# zig doesn't ship one, so pull in the mingw-w64 binutils.
				++ lib.optionals isWindows [ pkgs.pkgsCross.mingwW64.buildPackages.binutils ]
				# For re-signing the binaries after crane's reference rewriting,
				# see postFixup below.
				++ lib.optionals (target == "aarch64-apple-darwin") [ pkgs.rcodesign ];
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
					#
					# This has to extend the target-specific rustflags rather than set
					# RUSTFLAGS: cargo takes its flags from exactly one source, so
					# RUSTFLAGS would shadow the darwin SDK flags set below instead of
					# adding to them.
					export ${rustFlagsVar target}="''${${rustFlagsVar target}:-} --remap-path-prefix=$PWD=/build"
				'' + lib.optionalString isDarwin ''
					export MACOSX_DEPLOYMENT_TARGET=11.0
				'';
				# tls-webpki-roots + sqlite-bundled avoid linking against host
				# system libraries, which is required when cross-compiling.
				buildPhaseCargoCommand = ''
					cargoBuildLog=$(mktemp cargoBuildLogXXXX.json)
					cargo zigbuild --release --locked -p bark-cli --no-default-features --features tls-webpki-roots,sqlite-bundled --target ${zigbuildTarget target} --message-format json-render-diagnostics >"$cargoBuildLog"
				'';
			}
			// lib.optionalAttrs isDarwin {
				# Cross-compiling to macOS needs an Apple SDK to link system frameworks.
				SDKROOT = sdkroot;
				"${cFlagsVar target}"    = "-isysroot ${sdkroot} -iframework ${sdkroot}/System/Library/Frameworks";
				# -Wl,-S keeps debug info (STABS/DWARF) out of the binary. The
				# linker otherwise emits N_OSO stab entries for the debug info
				# shipped in the prebuilt std rlibs, and those embed object file
				# mtimes and rustc's randomly named link-stage temp dir, making
				# the output (via the LC_UUID content hash) nondeterministic.
				# The binaries are stripped anyway, so nothing of value is lost.
				#
				# -headerpad_max_install_names leaves room after the Mach-O load
				# commands. zig's linker emits zero padding, so the darwin stdenv's
				# fixup-phase signing hook cannot insert the LC_CODE_SIGNATURE load
				# command it needs and codesign_allocate aborts the build. (arm64
				# output is ad-hoc signed by the linker and already has the load
				# command, so only x86_64 tripped over this.)
				"${rustFlagsVar target}" = "-C link-arg=-isysroot -C link-arg=${sdkroot} -C link-arg=-F${sdkroot}/System/Library/Frameworks -C link-arg=-Wl,-S -C link-arg=-Wl,-headerpad_max_install_names";
			}
			// lib.optionalAttrs (target == "aarch64-apple-darwin") {
				# arm64 macOS refuses to run unsigned binaries. The linker
				# ad-hoc signs the output, but crane's postInstall hooks then
				# rewrite /nix/store reference strings inside it, invalidating
				# the signature. Re-sign as the very last step; rcodesign's
				# ad-hoc signing is deterministic so this keeps the build
				# reproducible.
				postFixup = ''
					for bin in "$out"/bin/*; do
						rcodesign sign "$bin"
					done
				'';
			}
		);

in lib.genAttrs targets mkTarget
