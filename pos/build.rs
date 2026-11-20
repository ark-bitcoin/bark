use std::env;
use std::fs;
use std::path::{Path, PathBuf};


fn main() {
	println!("cargo:rerun-if-changed=build.rs");
	generate_migrations("src/database/migrations", "migrations.rs");
	stage_web_dist();
}

/// Generates the embedded database migrations module.
///
/// refinery's embed_migrations! macro embeds the migration files in
/// filesystem readdir order, which makes the build unreproducible. This is
/// the same generator as in the server crate.
fn generate_migrations(dir: &str, out_file: &str) {
	println!("cargo:rerun-if-changed={}", dir);

	let mut files = fs::read_dir(dir)
		.expect("failed to read migrations directory")
		.map(|entry| entry.expect("failed to read migrations directory").path())
		.filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
		.collect::<Vec<_>>();
	files.sort();

	let mut code = String::from("pub fn runner() -> ::refinery::Runner {\n");
	code.push_str("\tlet migrations = vec![\n");
	for file in &files {
		let name = file.file_stem().unwrap().to_str()
			.expect("non-utf8 migration filename");
		let path = fs::canonicalize(file).unwrap();
		code.push_str(&format!(
			"\t\t::refinery::Migration::unapplied({:?}, include_str!({:?})).unwrap(),\n",
			name, path,
		));
	}
	code.push_str("\t];\n\t::refinery::Runner::new(&migrations)\n}\n");

	let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join(out_file);
	fs::write(out, code).expect("failed to write migrations module");
}

/// Stages the terminal PWA to embed in posd.
///
/// rust-embed needs the folder to exist at compile time, so the staging
/// directory is always created. It is filled from POS_WEB_DIST, or else from
/// web/dist when the PWA was built in place. Without either, posd serves no
/// terminal.
fn stage_web_dist() {
	println!("cargo:rerun-if-env-changed=POS_WEB_DIST");

	let staging = PathBuf::from(env::var("OUT_DIR").unwrap()).join("web-dist");
	if staging.exists() {
		fs::remove_dir_all(&staging).expect("failed to clear the web staging directory");
	}
	fs::create_dir_all(&staging).expect("failed to create the web staging directory");

	let dist = match env::var("POS_WEB_DIST") {
		Ok(dist) => PathBuf::from(dist),
		Err(_) => PathBuf::from("web/dist"),
	};
	println!("cargo:rerun-if-changed={}", dist.display());
	if dist.join("index.html").is_file() {
		copy_dir(&dist, &staging).expect("failed to copy the PWA distribution");
	}
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
	for entry in fs::read_dir(src)? {
		let entry = entry?;
		let dest = dst.join(entry.file_name());
		if entry.file_type()?.is_dir() {
			fs::create_dir_all(&dest)?;
			copy_dir(&entry.path(), &dest)?;
		} else {
			fs::copy(entry.path(), &dest)?;
		}
	}
	Ok(())
}
