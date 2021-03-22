use std::path::PathBuf;

fn main() {
    // XXX TODO add header to file with "auto-generated"
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=src/proto/");
    // XXX TODO instead it could be nice to separate the file, the types.rs into
    // lib/ and the client|server into bin/anoma-node/rpc & bin/anoma-client/rpc
    tonic_build::configure()
        .out_dir(PathBuf::from("src/lib/protobuf"))
        .format(true)
        // XXX TODO try to add json encoding to simplify use for user
        // .type_attribute("types.Intent", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile(&["src/proto/services.proto"], &["src/proto"])
        .unwrap();
}
