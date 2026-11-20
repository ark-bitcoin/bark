{
	craneLib, pkgs, lib,
	gitHash ? "unknown",
}:

# posd, the point-of-sale service, with its terminal PWA embedded.
#
# posd is deployed by the operator next to captaind, so it is built for the
# host only, with the stdenv toolchain. The PWA is built from the committed
# package-lock.json and handed to pos/build.rs through POS_WEB_DIST.

let
	crateInfo = craneLib.crateNameFromCargoToml {
		cargoToml = ./../pos/Cargo.toml;
	};

	webDist = pkgs.buildNpmPackage {
		pname = "scuttle-pos-web";
		version = crateInfo.version;
		src = lib.fileset.toSource {
			root = ./../pos/web;
			fileset = lib.fileset.difference ./../pos/web (lib.fileset.unions [
				(lib.fileset.maybeMissing ./../pos/web/node_modules)
				(lib.fileset.maybeMissing ./../pos/web/dist)
			]);
		};
		# Reads the dependency hashes from package-lock.json, so no separate
		# npmDepsHash has to be kept in sync.
		npmDeps = pkgs.importNpmLock { npmRoot = ./../pos/web; };
		npmConfigHook = pkgs.importNpmLock.npmConfigHook;
		installPhase = ''
			cp -r dist $out
		'';
	};

	src = lib.fileset.toSource {
		root = ./..;
		fileset = lib.fileset.unions [
			(craneLib.fileset.commonCargoSources ./..)
			./../server-rpc/protos
			./../cln-rpc/protos
			./../pos/src/database/migrations
			# Migrations of crates in the workspace build graph.
			./../server/src/database/migrations
			./../server/src/database/migrations_expiry_payout
		];
	};
in
craneLib.buildPackage {
	pname = "scuttle-pos";
	version = crateInfo.version;
	inherit src;
	cargoVendorDir = craneLib.vendorCargoDeps { inherit src; };
	strictDeps = true;
	doCheck = false;
	cargoExtraArgs = "--locked -p scuttle-pos";

	nativeBuildInputs = with pkgs; [
		pkg-config
		protobuf
		llvmPackages.clang-unwrapped
	];

	GIT_HASH = gitHash;
	POS_WEB_DIST = webDist;
	LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";

	passthru = { inherit webDist; };
}
