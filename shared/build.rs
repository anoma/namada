use std::env;

fn main() {
    // Tell Cargo to build when the `ANOMA_DEV` env var changes
    println!("cargo:rerun-if-env-changed=ANOMA_DEV");
    // Enable "dev" feature if `ANOMA_DEV` is trueish
    if let Ok(dev) = env::var("ANOMA_DEV") {
        if dev.to_ascii_lowercase().trim() == "true" {
            println!("cargo:rustc-cfg=feature=\"dev\"");
        }
    }
}
