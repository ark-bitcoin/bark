fn main() {
	tonic_build::configure()
		.build_client(true)
		.out_dir("src/grpc")
		.compile(&["./protos/node.proto"], &["./protos/"])
		.expect("Failed to compile cln server protos");
}
