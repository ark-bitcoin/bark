fn main() {
	tonic_build::configure()
		.build_client(true)
		.out_dir("src/grpc")
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile_protos(&["./protos/node.proto"], &["./protos/"])
		.expect("Failed to compile cln server protos");
}
