use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

fn main() {
    println!("cargo:rerun-if-changed=CONSENSUS_VERSION");
    let out_dir = env::var("OUT_DIR").unwrap();
    let raw_consensus_version = std::fs::read_to_string("./CONSENSUS_VERSION")
        .expect("Read CONSENSUS_VERSION file");
    let consensus_version = u64::from_str(raw_consensus_version.trim())
        .expect("CONSENSUS_VERSION contains a u64");
    let mut consensus_version_rs =
        File::create(PathBuf::from_iter([&out_dir, "consensus_version.rs"]))
            .expect("cannot write consensus version");
    let pre = "/// Get the current consensus version\npub fn \
               consensus_version() -> u64 { ";
    let post = " }";
    consensus_version_rs
        .write_all(pre.as_bytes())
        .expect("cannot write consensus version");
    consensus_version_rs
        .write_all(consensus_version.to_string().as_bytes())
        .expect("cannot write consensus version");
    consensus_version_rs
        .write_all(post.as_bytes())
        .expect("cannot write consensus version");
}
