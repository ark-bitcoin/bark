# The swagger-ui distribution bundled into barkd by the utoipa-swagger-ui
# build script. Pinning it in the store and pointing the build script at it
# via SWAGGER_UI_DOWNLOAD_URL keeps builds from downloading it from GitHub,
# which also makes the feature buildable inside the nix sandbox (no network).
# Keep the version in sync with what the utoipa-swagger-ui crate expects.
{ pkgs }:
pkgs.fetchurl {
	url = "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v5.30.2.zip";
	hash = "sha256-v25kISZOrS4HqLXeszwik18aYUHQ6K4n9kV8Ps9ciog=";
}
