use std::{env, path::PathBuf};

fn main() -> Result<(), ()> {
  println!("cargo:rerun-if-changed=build.rs");
  println!("cargo:rerun-if-changed=wrapper.h");
  println!("cargo:rerun-if-changed=Cargo.lock");
  // The bindgen::Builder is the main entry point
  // to bindgen, and lets you build up options for
  // the resulting bindings.
  let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .rustfmt_bindings(true)
        .whitelist_var("curve25519_.*")
        .whitelist_type("curve25519_.*")
        .whitelist_function("curve25519_.*")
        .whitelist_var("xed25519_.*")
        .whitelist_type("xed25519_.*")
        .whitelist_function("xed25519_.*")
        .whitelist_var("generalized_.*")
        .whitelist_type("generalized_.*")
        .whitelist_function("generalized_.*")
        .rust_target(bindgen::RustTarget::Nightly)
        // Finish the builder and generate the bindings.
        .generate()?;
  // Write the bindings to the $OUT_DIR/bindings.rs file.
  let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
  bindings
    .write_to_file(out_path.join("bindings.rs"))
    .expect("Couldn't write bindings!");

  let dst = cmake::build("curve25519-c");
  println!("cargo:rustc-link-search=native={}", dst.display());
  println!("cargo:rustc-flags=-L {}/lib", dst.display());
  println!("cargo:rustc-link-lib=static=curve25519");
  Ok(())
}
