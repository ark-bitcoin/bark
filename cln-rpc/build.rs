fn main() {
	tonic_prost_build::configure()
		.build_client(true)
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile_protos(&["./protos/node.proto"], &["./protos/"])
		.expect("Failed to compile cln server protos");

	println!("cargo:rerun-if-changed=protos/node.proto");

	tonic_prost_build::configure()
		.build_client(true)
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile_protos(&["./protos/hold.proto"], &["./protos/"])
		.expect("Failed to compile hold invoice plugin server protos");

	println!("cargo:rerun-if-changed=protos/hold.proto");
}
