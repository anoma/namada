# `make fmt`, `make clippy` and their `check` variants won't work inside nix-shell
# because nix doesn't use rustup's cargo, but you can run it on nixOS outside nix-shell.

let
  rust_overlay = import (builtins.fetchTarball
    "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");

  pkgs = import <nixpkgs> { overlays = [ rust_overlay ]; };

  rust = (pkgs.rust-bin.stable.latest.minimal.override {
    targets = [ "x86_64-unknown-linux-gnu" "wasm32-unknown-unknown" ];
  });
in with pkgs;
stdenv.mkDerivation {
  name = "anoma-rust";

  buildInputs = [ rust clang llvmPackages.libclang olm tendermint protobuf ];

  shellHook = ''
    export LIBCLANG_PATH="${pkgs.llvmPackages.libclang}/lib";
    export PROTOC="${pkgs.protobuf}/bin/protoc";
    export PROTOC_INCLUDE="${pkgs.protobuf}/include"
  '';
}
