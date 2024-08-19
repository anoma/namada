/// Set `is_apple_silicon` flag to avoid a wasm compilation error
fn main() {
    let host_arch =
        std::env::var("HOST").expect("HOST environment variable not found");

    if host_arch == "aarch64-apple-darwin" {
        println!("cargo:rustc-cfg=is_apple_silicon");
        println!("cargo::rustc-check-cfg=cfg(is_apple_silicon)");
    }
}
