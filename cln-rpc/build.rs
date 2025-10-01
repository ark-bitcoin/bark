fn main() {
	tonic_prost_build::configure()
		.build_client(true)
		.out_dir("src/")
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile_protos(&["./protos/node.proto"], &["./protos/"])
		.expect("Failed to compile cln server protos");

	println!("cargo:rerun-if-changed=src/cln.rs");
	println!("cargo:rerun-if-changed=protos/node.proto");

	tonic_prost_build::configure()
		.build_client(true)
		.out_dir("src/plugins/")
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile_protos(&["./protos/hold.proto"], &["./protos/"])
		.expect("Failed to compile hold invoice plugin server protos");

	println!("cargo:rerun-if-changed=src/plugins/hold/hold.rs");
	println!("cargo:rerun-if-changed=protos/protos/hold.proto");
}
