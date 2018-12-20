use std::env;
use std::path::PathBuf;

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
        .whitelist_var("RATCHET_.*")
        .whitelist_var("SG_.*")
        .whitelist_var("KEY_EXCHANGE_.*")
        .whitelist_var("CIPHERTEXT_.*")
        .whitelist_var("KEY_EXCHANGE_.*")
        .whitelist_type("signal_.*")
        .whitelist_type("session_.*")
        .whitelist_type("sender_.*")
        .whitelist_type("retchat_.*")
        .whitelist_type("curve_.*")
        .whitelist_type("ec_.*")
        .whitelist_type("ciphertext_.*")
        .whitelist_function("signal_.*")
        .whitelist_function("session_.*")
        .whitelist_function("sender_.*")
        .whitelist_function("retchat_.*")
        .whitelist_function("curve_.*")
        .whitelist_function("ec_.*")
        .whitelist_function("ciphertext_.*")
        .whitelist_function("pre_key.*")
        .whitelist_function("hkdf_.*")
        .rust_target(bindgen::RustTarget::Nightly)
        // Finish the builder and generate the bindings.
        .generate()?;
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let dst = cmake::build("libsignal-protocol-c");
    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-flags=-L {}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=signal-protocol-c");
    Ok(())
}
