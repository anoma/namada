use std::path::PathBuf;

fn main() {
    // XXX TODO add header to file with "auto-generated"
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=src/proto/");
    // XXX TODO instead it could be nice to separate the file, the types.rs into
    // lib/ and the clien|server into bin/anoma-node/rpc
    tonic_build::configure()
        .out_dir(PathBuf::from("src/lib/protobuf"))
        .format(true)
        // XXX TODO can this be automatic for all type in a file ?
        .type_attribute("types.IntentMessage", "#[derive(Hash)]")
        .type_attribute("types.DkgMessage", "#[derive(Hash)]")
        .type_attribute("types.Intent", "#[derive(Hash)]")
        .compile(&["src/proto/services.proto"], &["src/proto"])
        .unwrap();
}
