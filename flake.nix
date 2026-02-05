{
	description = "ark";

	inputs = {
		nixpkgs.url = "nixpkgs/nixos-25.05";
		nixpkgs-master.url = "github:NixOS/nixpkgs/master";
		flake-utils.url = "github:numtide/flake-utils";
		fenix = {
			url = "github:nix-community/fenix";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = { self, nixpkgs, nixpkgs-master, flake-utils, fenix }:
		flake-utils.lib.eachDefaultSystem (system:
			let
				rustVersion = "1.90.0";

				pkgs = import nixpkgs {
					inherit system;
					config = { allowUnfree = true; };
				};
				lib = pkgs.lib;

				isDarwin = pkgs.stdenv.hostPlatform.isDarwin;

				masterPkgs = import nixpkgs-master {
					inherit system;
				};

				rustToolchain = fenix.packages.${system}.fromToolchainName {
					name = rustVersion;
					sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
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
									then "\(.slog_id) - \(.message): \(.slog_data_json)"
									else "\(.message)"
									end
								)"
							';
							'';
						})
					];
				};
			in
			{
				packages = {
					"slog-tools" = slog-tools;
				};

				# NB each of our shell files exposes a `env` and a `shell` which respectively
				# contain only the env variables and the actual shell.
				# This enables one shell inheriting the env vars from another shell.
				devShells = let
					buildShell = import ./nix/build-shell.nix {
						inherit pkgs lib rustToolchain;
					};

					devShell = import ./nix/dev-shell.nix {
						inherit system pkgs masterPkgs lib fenix buildShell slog-tools;
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

					# In this shell we expose the Rust version required to build for the
					# ark-lib MSRV.
					msrv-lib = libMsrvShell.shell;
				};
			}
		);
}
