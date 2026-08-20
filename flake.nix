{
	description = "ark";

	nixConfig = {
		extra-substituters = [ "https://bark.cachix.org" ];
		extra-trusted-public-keys = [ "bark.cachix.org-1:Iaihe4ABbOQz1CHBoYUZS/sHVAcISasJZ+lL3I4gRB0=" ];
	};

	inputs = {
		nixpkgs.url = "nixpkgs/nixos-26.05";
		# nixpkgs-master.url = "github:NixOS/nixpkgs/master";
		flake-utils.url = "github:numtide/flake-utils";
		crane.url = "github:ipetkov/crane";
		fenix = {
			url = "github:nix-community/fenix";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = { self, nixpkgs, flake-utils, crane, fenix }:
		flake-utils.lib.eachDefaultSystem (system:
			let
				rustVersion = "1.90.0";

				pkgs = import nixpkgs {
					inherit system;
					config = { allowUnfree = true; };
				};
				lib = pkgs.lib;

				# Pin the zig version explicitly so a future nixpkgs bump can't
				# silently swap the linker under the release builds and break
				# their reproducibility. cargo-zigbuild is wrapped with its zig
				# input force-prepended to PATH, so it must be rewired too.
				zigRelease = pkgs.zig_0_16;
				releasePkgs = pkgs // {
					zig = zigRelease;
					cargo-zigbuild = pkgs.cargo-zigbuild.override {
						zig = zigRelease;
					};
				};

				isDarwin = pkgs.stdenv.hostPlatform.isDarwin;

				# We serve the static musl binaries for Linux user so it runs everywhere.
				hostRustTarget =
					let t = pkgs.stdenv.hostPlatform.rust.rustcTarget;
					in if pkgs.stdenv.hostPlatform.isLinux
						then builtins.replaceStrings ["-gnu"] ["-musl"] t
						else t;

				rustToolchain = fenix.packages.${system}.fromToolchainName {
					name = rustVersion;
					sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
				};

				craneLib = (crane.mkLib pkgs).overrideToolchain (fenix.packages.${system}.combine [
					rustToolchain.toolchain
					# Provides rust-objcopy, which rustc invokes to implement
					# -C strip for Mach-O targets (ELF and PE strip via the linker).
					rustToolchain.llvm-tools-preview
					(fenix.packages.${system}.targets.x86_64-unknown-linux-gnu.fromToolchainName {
						name = rustVersion;
						sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
					}).rust-std
					(fenix.packages.${system}.targets.x86_64-unknown-linux-musl.fromToolchainName {
						name = rustVersion;
						sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
					}).rust-std
					(fenix.packages.${system}.targets.aarch64-unknown-linux-musl.fromToolchainName {
						name = rustVersion;
						sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
					}).rust-std
					(fenix.packages.${system}.targets.armv7-unknown-linux-musleabihf.fromToolchainName {
						name = rustVersion;
						sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
					}).rust-std
					(fenix.packages.${system}.targets.x86_64-apple-darwin.fromToolchainName {
						name = rustVersion;
						sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
					}).rust-std
					(fenix.packages.${system}.targets.aarch64-apple-darwin.fromToolchainName {
						name = rustVersion;
						sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
					}).rust-std
					(fenix.packages.${system}.targets.x86_64-pc-windows-gnu.fromToolchainName {
						name = rustVersion;
						sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
					}).rust-std
				]);

				rustTargetWasm = (fenix.packages.${system}.targets.wasm32-unknown-unknown.fromToolchainName {
					name = rustVersion;
					sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
				}).rust-std;

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

				slog-tools = pkgs.symlinkJoin {
					name = "bark-slog-tools";
					paths = [
						(slogJq "slmod" ''select((.target | split("::") | index($arg)) != null)'')
						(slogJq "sls" ''select(.slog_id != null)'')
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
								"[\(time_ms3(.timestamp)) \(rpad(5; .level)) \(rpad(17; "\(.target)]"))  \(
									if .slog_id != null
									then "\(.slog_id) - \(.message): \(.slog_data)"
									else "\(.message)"
									end
								)"
							';
							'';
						})
					];
				};

				barkPackages = import ./nix/package-bark.nix {
					pkgs = releasePkgs;
					inherit lib craneLib;
					gitHash = self.rev or self.dirtyRev or "unknown";
					targets = [
						"x86_64-unknown-linux-gnu"
						"x86_64-unknown-linux-musl"
						"aarch64-unknown-linux-musl"
						"armv7-unknown-linux-musleabihf"
						"x86_64-apple-darwin"
						"aarch64-apple-darwin"
						"x86_64-pc-windows-gnu"
					];
				};

				serverPackages = import ./nix/package-server.nix {
					pkgs = releasePkgs;
					inherit lib craneLib;
					gitHash = self.rev or self.dirtyRev or "unknown";
					targets = [
						"x86_64-unknown-linux-gnu"
						"x86_64-unknown-linux-musl"
					];
				};
			in
			{
				packages = {
					"slog-tools" = slog-tools;

					# Release artifacts keyed by target triple.
					bark-x86_64-unknown-linux-gnu  = barkPackages.x86_64-unknown-linux-gnu;
					bark-x86_64-unknown-linux-musl = barkPackages.x86_64-unknown-linux-musl;
					bark-aarch64-unknown-linux-musl = barkPackages.aarch64-unknown-linux-musl;
					bark-armv7-unknown-linux-musleabihf = barkPackages.armv7-unknown-linux-musleabihf;
					bark-x86_64-apple-darwin       = barkPackages.x86_64-apple-darwin;
					bark-aarch64-apple-darwin      = barkPackages.aarch64-apple-darwin;
					bark-x86_64-pc-windows-gnu     = barkPackages.x86_64-pc-windows-gnu;

					# Release artifacts keyed by target triple.
					bark-server-x86_64-unknown-linux-gnu  = serverPackages.x86_64-unknown-linux-gnu;
					bark-server-x86_64-unknown-linux-musl = serverPackages.x86_64-unknown-linux-musl;
				}
				# `bark` and `bark-server` build for the current system. Only
				# defined when the host triple is one of the packaged targets.
				# Elsewhere nix fails with a clear "does not provide attribute" error.
				// lib.optionalAttrs (builtins.hasAttr hostRustTarget barkPackages) {
					bark = barkPackages.${hostRustTarget};
				}
				// lib.optionalAttrs (builtins.hasAttr hostRustTarget serverPackages) {
					bark-server = serverPackages.${hostRustTarget};
				};

				# for `nix run` support
				apps = let
					mkApp = drv: bin: {
						type = "app";
						program = "${drv}/bin/${bin}";
						meta.description = "Runs the ${bin} binary built for the current system";
					};
				in lib.optionalAttrs (builtins.hasAttr hostRustTarget barkPackages) {
					bark  = mkApp barkPackages.${hostRustTarget} "bark";
					barkd = mkApp barkPackages.${hostRustTarget} "barkd";
				} // lib.optionalAttrs (builtins.hasAttr hostRustTarget serverPackages) {
					captaind  = mkApp serverPackages.${hostRustTarget} "captaind";
					watchmand = mkApp serverPackages.${hostRustTarget} "watchmand";
				};

				# NB each of our shell files exposes a `env` and a `shell` which respectively
				# contain only the env variables and the actual shell.
				# This enables one shell inheriting the env vars from another shell.
				devShells = let
					buildShell = import ./nix/build-shell.nix {
						inherit pkgs lib rustToolchain;
					};

					devShell = import ./nix/dev-shell.nix {
						inherit system pkgs lib fenix buildShell slog-tools rustTargetWasm;
					};

					ciShell = import ./nix/ci-shell.nix {
						inherit pkgs devShell;
					};

					libMsrvShell =
						let
							rustVersion = "1.74.0";
							rustToolchain = fenix.packages.${system}.fromToolchainName {
								name = rustVersion;
								sha256 = "sha256-U2yfueFohJHjif7anmJB5vZbpP7G6bICH4ZsjtufRoU=";
							};
						in import ./nix/build-shell.nix {
							inherit pkgs lib rustToolchain;
						};
				in {
					# The default shell is used for development and contains all
					# tools that we use for running unit and integration tests.
					default = devShell.shell;

					# Exposes a minimal shell to build our project.
					build = buildShell.shell;

					# Extends `default` with CI-only env (currently just
					# RUSTC_WRAPPER=sccache) so cargo actually picks up the
					# wrapper when invoked from CI jobs. Kept separate so local
					# devs entering `nix develop .#default` aren't implicitly
					# opted into sccache.
					ci = ciShell.shell;

					# In this shell we expose the Rust version required to build for the
					# ark-lib MSRV.
					msrv-lib = libMsrvShell.shell;
				};
			}
		);
}
