use std::{env, str};

/// Path to the .proto source files, relative to `tx` crate directory
const PROTO_SRC: &str = "./proto";

fn main() {
    if let Ok(val) = env::var("COMPILE_PROTO") {
        if val.eq_ignore_ascii_case("false") {
            // Skip compiling proto files
            return;
        }
    }

    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed={}", PROTO_SRC);

    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&[format!("{}/types.proto", PROTO_SRC)], &[PROTO_SRC])
        .unwrap();
}
