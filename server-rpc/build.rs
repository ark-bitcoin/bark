fn main() {
	let protos = &["./protos/bark_server.proto"];

	tonic_build::configure()
		.build_server(cfg!(feature = "server"))
		.build_client(true)
		.out_dir("./src/")
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile_protos(protos, &[] as &[&str])
		.expect("failed to compile bark server protos");

	println!("cargo:rerun-if-changed=src/bark_server.rs");
	println!("cargo:rerun-if-changed=protos/bark_server.proto");
}
