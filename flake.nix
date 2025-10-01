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
				rustBuildToolchain = fenix.packages.${system}.combine [
					rustToolchain.rustc
					rustToolchain.cargo
					rustToolchain.rust-src
					rustToolchain.llvm-tools
					rustToolchain.rust-std
				];
			in
			{
				devShells.default = import ./nix/dev-shell.nix {
					inherit pkgs masterPkgs lib rustToolchain rustBuildToolchain;
				};
			}
		);
}
