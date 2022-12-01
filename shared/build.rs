use std::env;

fn main() {
    // Tell Cargo to build when the `NAMADA_DEV` env var changes
    println!("cargo:rerun-if-env-changed=NAMADA_DEV");
    // Enable "dev" feature if `NAMADA_DEV` is trueish
    if let Ok(dev) = env::var("NAMADA_DEV") {
        if dev.to_ascii_lowercase().trim() == "true" {
            println!("cargo:rustc-cfg=feature=\"dev\"");
        }
    }
}
