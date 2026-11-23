# Builds the pinned CLN hold plugin as a binary that runs on plain Debian 12.
#
# The hold source (revision and hash) is read from nix/dev-shell.nix of the
# commit being built, so the deployed plugin is built from exactly the pin the
# integration tests use. We do not reuse the dev shell's derivation because its
# output cannot run on Debian 12: nixpkgs 26.05 builds against glibc >= 2.38,
# whose headers turn strtol and sscanf into __isoc23_strtol and
# __isoc23_sscanf whenever _GNU_SOURCE is defined (libgit2 does), and Debian 12
# ships glibc 2.36. We link two tiny definitions of those symbols into the
# plugin, which forward to the plain strtol/sscanf. They differ only in that
# the C23 variants also accept "0b" binary prefixes. `build.sh` fails if the
# result needs a glibc newer than 2.36 for any other reason.
#
# The result links against the host's libc, libpq and sqlite (Debian packages
# libc6, libpq5, libsqlite3-0): we rewrite the ELF interpreter, rpath and the
# sqlite soname so it needs no nix on the target.
#
# Usage:
#   nix build --impure --file hold-plugin.nix --argstr flake "git+file:///srv/scuttle/src?rev=<commit>"
{ flake }:
let
	fl = builtins.getFlake flake;
	system = "x86_64-linux";
	pkgs = fl.inputs.nixpkgs.legacyPackages.${system};
	lib = pkgs.lib;

	pinLines = lib.splitString "\n" (builtins.readFile "${fl.outPath}/nix/dev-shell.nix");
	firstMatch = re: lib.findFirst (m: m != null) (throw "pin not found: ${re}")
		(map (builtins.match re) pinLines);
	holdRev = builtins.head (firstMatch ''[[:space:]]*holdPluginRevision = "([0-9a-f]{40})";.*'');
	# The `hash = ...` line of the fetchFromGitLab for repo "hold".
	repoIdx = builtins.head (builtins.filter
		(i: builtins.match ''[[:space:]]*repo = "hold";.*'' (builtins.elemAt pinLines i) != null)
		(lib.range 0 (builtins.length pinLines - 1)));
	holdHash = builtins.head (builtins.match ''[[:space:]]*hash = "(sha256-[^"]+)";.*''
		(builtins.elemAt pinLines (repoIdx + 2)));

	# Defined through asm labels so the calls bind to glibc's plain symbols
	# instead of being redirected back to the __isoc23 names.
	compatShim = pkgs.runCommandCC "glibc-isoc23-shim.o" {} ''
		cat > shim.c <<-'EOC'
		#include <stdarg.h>
		#include <stdio.h>
		extern long plain_strtol(const char *, char **, int) __asm__("strtol");
		extern int plain_vsscanf(const char *, const char *, va_list) __asm__("vsscanf");
		long __isoc23_strtol(const char *s, char **e, int b) { return plain_strtol(s, e, b); }
		int __isoc23_sscanf(const char *s, const char *f, ...) {
			va_list ap; va_start(ap, f);
			int r = plain_vsscanf(s, f, ap);
			va_end(ap);
			return r;
		}
		EOC
		$CC -std=gnu17 -O2 -fPIC -c shim.c -o $out
	'';

	src = pkgs.fetchFromGitLab {
		owner = "ark-bitcoin";
		repo = "hold";
		rev = holdRev;
		hash = holdHash;
	};

	hold = pkgs.rustPlatform.buildRustPackage {
		pname = "hold";
		version = holdRev;
		inherit src;
		cargoLock.lockFile = "${src}/Cargo.lock";
		nativeBuildInputs = [ pkgs.protobuf pkgs.rustPlatform.bindgenHook pkgs.go pkgs.git pkgs.perl ];
		buildInputs = [ pkgs.sqlite pkgs.postgresql_17 ];
		doCheck = false;
		preBuild = ''
			export RUSTFLAGS="''${RUSTFLAGS:-} -C link-arg=${compatShim}"
		'';
	};
in pkgs.runCommand "hold-plugin-debian" {
	nativeBuildInputs = [ pkgs.patchelf pkgs.binutils ];
	inherit hold;
	passthru = { inherit holdRev holdHash; };
} ''
	mkdir -p $out/bin
	cp $hold/bin/hold $out/bin/hold
	chmod u+w $out/bin/hold
	patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 \
		--set-rpath /usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu \
		--replace-needed libsqlite3.so libsqlite3.so.0 \
		$out/bin/hold
	# Record the needed libs and highest glibc symbol version for the manifest.
	patchelf --print-needed $out/bin/hold > $out/needed-libs.txt
	objdump -T $out/bin/hold | grep -o 'GLIBC_[0-9.]*' | sort -Vu > $out/glibc-symbols.txt
	echo ${holdRev} > $out/rev
''
