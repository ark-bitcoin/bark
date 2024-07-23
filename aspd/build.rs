fn main() {
	let protos = &["rpc-protos/aspd.proto"];

	// server
	tonic_build::configure()
		.build_server(true)
		.build_client(false)
		.out_dir("src/rpc")
		.compile(protos, &[] as &[&str])
		.expect("failed to compile aspd server protos");

	// client
	tonic_build::configure()
		.build_client(true)
		.build_server(false)
		.out_dir("../aspd-rpc-client/src/")
		.compile(protos, &[] as &[&str])
		.expect("failed to compile aspd client protos");
}
