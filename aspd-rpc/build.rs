fn main() {
	let protos = &["./rpc-protos/aspd.proto"];

	tonic_build::configure()
		.build_server(cfg!(feature = "server"))
		.build_client(true)
		.out_dir("./src/")
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile_protos(protos, &[] as &[&str])
		.expect("failed to compile aspd protos");
}
