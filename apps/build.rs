/// Path to the .proto source files, relative to `apps` directory
const PROTO_SRC: &str = "../proto";

fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed={}", PROTO_SRC);
    tonic_build::configure()
        .out_dir("src/lib/proto/generated")
        .format(true)
        // TODO try to add json encoding to simplify use for user
        // .type_attribute("types.Intent", "#[derive(serde::Serialize,
        // serde::Deserialize)]")
        .compile(
            &[format!("{}/services.proto", PROTO_SRC)],
            &[PROTO_SRC.into()],
        )
        .unwrap();
}
