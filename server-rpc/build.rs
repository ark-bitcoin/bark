
fn main() {
	tonic_prost_build::configure()
		.build_server(cfg!(feature = "server"))
		.build_client(true)
		.protoc_arg("--experimental_allow_proto3_optional")
		.compile_protos(&[
			"./protos/core.proto",
			"./protos/bark_server.proto",
			"./protos/intman.proto",
			"./protos/mailbox_server.proto",
		], &["./protos"])
		.expect("failed to compile bark server rpc protos");

	println!("cargo:rerun-if-changed=protos/core.proto");
	println!("cargo:rerun-if-changed=protos/bark_server.proto");
	println!("cargo:rerun-if-changed=protos/intman.proto");
	println!("cargo:rerun-if-changed=protos/mailbox_server.proto");
	println!("cargo:rerun-if-changed=src/core.rs");
	println!("cargo:rerun-if-changed=src/bark_server.rs");
	println!("cargo:rerun-if-changed=src/intman.rs");
	println!("cargo:rerun-if-changed=src/mailbox_server.rs");
}
