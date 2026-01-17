use std::fs;
use std::io::Write;
use std::path::Path;

use prost::Message;

fn main() {
	let out_dir = std::env::var("OUT_DIR").unwrap();
	let descriptor_path = Path::new(&out_dir).join("file_descriptor_set.bin");

	tonic_prost_build::configure()
		.build_server(cfg!(feature = "server"))
		.build_client(true)
		.protoc_arg("--experimental_allow_proto3_optional")
		.file_descriptor_set_path(&descriptor_path)
		.compile_protos(&[
			"./protos/core.proto",
			"./protos/bark_server.proto",
			"./protos/intman.proto",
			"./protos/mailbox_server.proto",
		], &["./protos"])
		.expect("failed to compile bark server rpc protos");

	generate_method_lookup(&descriptor_path, &out_dir);

	println!("cargo:rerun-if-changed=protos/core.proto");
	println!("cargo:rerun-if-changed=protos/bark_server.proto");
	println!("cargo:rerun-if-changed=protos/intman.proto");
	println!("cargo:rerun-if-changed=protos/mailbox_server.proto");
	println!("cargo:rerun-if-changed=src/core.rs");
	println!("cargo:rerun-if-changed=src/bark_server.rs");
	println!("cargo:rerun-if-changed=src/intman.rs");
	println!("cargo:rerun-if-changed=src/mailbox_server.rs");
}

fn generate_method_lookup(descriptor_path: &Path, out_dir: &str) {
	let bytes = fs::read(descriptor_path).expect("failed to read file descriptor set");
	let fds = prost_types::FileDescriptorSet::decode(&bytes[..])
		.expect("failed to decode FileDescriptorSet");

	let mut entries = Vec::new();

	for file in &fds.file {
		let package = file.package.as_deref().unwrap_or("");
		for service in &file.service {
			let service_name = service.name.as_deref().unwrap_or("");
			for method in &service.method {
				let method_name = method.name.as_deref().unwrap_or("");
				// Wire format path: /package.Service/Method
				let path = format!("/{}.{}/{}", package, service_name, method_name);
				entries.push((path, service_name.to_string(), method_name.to_string()));
			}
		}
	}

	let dest = Path::new(out_dir).join("grpc_methods.rs");
	let mut f = fs::File::create(&dest).expect("failed to create grpc_methods.rs");

	writeln!(f, "/// Generated from proto files - DO NOT EDIT").unwrap();
	writeln!(f, "/// Returns (service, method) using wire format (PascalCase)").unwrap();
	writeln!(f, "pub fn lookup_grpc_method(path: &str) -> (&'static str, &'static str) {{").unwrap();
	writeln!(f, "\tmatch path {{").unwrap();
	for (path, service, method) in &entries {
		writeln!(f, "\t\t\"{}\" => (\"{}\", \"{}\"),", path, service, method).unwrap();
	}
	writeln!(f, "\t\t_ => (\"unknown\", \"unknown\"),").unwrap();
	writeln!(f, "\t}}").unwrap();
	writeln!(f, "}}").unwrap();
}
