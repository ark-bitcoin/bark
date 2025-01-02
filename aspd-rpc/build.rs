fn main() {
	let protos = &["./rpc-protos/aspd.proto"];

	tonic_build::configure()
		.build_server(cfg!(feature = "server-rpc"))
		.build_client(true)
		.out_dir("./src/rpc")
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile(protos, &[] as &[&str])
		.expect("failed to compile aspd protos");
}
