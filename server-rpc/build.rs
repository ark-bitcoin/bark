use std::fs;

fn main() {
	fs::create_dir_all("./src/protos").expect("error creating src/protos dir");

	tonic_build::configure()
		.build_server(cfg!(feature = "server"))
		.build_client(true)
		.out_dir("./src/protos/")
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile_protos(&[
			"./protos/bark_server.proto",
			"./protos/intman.proto",
		], &[] as &[&str])
		.expect("failed to compile bark server protos");

	println!("cargo:rerun-if-changed=protos/bark_server.proto");
	println!("cargo:rerun-if-changed=protos/intman.proto");
	println!("cargo:rerun-if-changed=src/bark_server.rs");
	println!("cargo:rerun-if-changed=src/intman.rs");
}
