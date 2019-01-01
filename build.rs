fn main() {
  let protos = [
    "protobuf/FingerprintProtocol.proto",
    "protobuf/LocalStorageProtocol.proto",
    "protobuf/WhisperTextProtocol.proto",
  ];

  for file in protos.iter() {
    println!("cargo:rerun-if-changed={}", file);
  }

  println!("cargo:rerun-if-changed=build.rs");
  prost_build::compile_protos(&protos, &["protobuf/"]).unwrap();
}
