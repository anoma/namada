{
  description = "Namada";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/master";
  inputs.utils.url = "github:numtide/flake-utils";
  inputs.rust-overlay.url = "github:oxalica/rust-overlay";

  outputs = {
    self,
    nixpkgs,
    utils,
    rust-overlay,
  }:
    utils.lib.eachDefaultSystem (system: let
      overlays = [
        (import rust-overlay)
      ];
      pkgs = import nixpkgs rec {
        inherit system overlays;
      };
      rust = pkgs.rust-bin.stable.latest.default.override {
        extensions = [ "rust-src" ];
      };
      buildRustPackage =
        (pkgs.makeRustPlatform {
          cargo = rust;
          rustc = rust;
        })
        .buildRustPackage;
      myNativeBuildInputs = with pkgs;
        [
          pkg-config
          protobuf
          libclang.lib
          makeWrapper
        ]
        ++ lib.optionals stdenv.isLinux
        (with pkgs; [
          cargo-kcov
        ]);
      myBuildInputs = with pkgs;
        [
          openssl
          systemd
        ]
        ++ lib.optionals stdenv.isDarwin
        (with darwin.apple_sdk.frameworks; [
          Security
        ]);
      myBuildRustPackage = attrs:
        buildRustPackage (with pkgs; {
            version = self.dirtyShortRev;
            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = {
                "borsh-ext-1.2.0" = "sha256-nQadqyeAY0/gEMLBkpqtSm5D7kV+r3LVT/Cg2oTV7Ug=";
                "clru-0.5.0" = "sha256-/1NfKqcWGCyF3+f0v2CnuFmNjjKkzfvYcX+GzxLwz7s=";
                "config-0.14.0" = "sha256-VKp07nZERS9H7MdYwmuuuobdqvwec9704BdW6lcIhUc=";
                "ethbridge-bridge-contract-0.24.0" = "sha256-qs81bIWKk4oxh6nFWqAt4eBbPuIWF2a3ytUSjDJZWSU=";
                "index-set-0.8.0" = "sha256-oxJfQdKnYiW5VbMPuukVyDY5n8mys31hYNrJF89nXhY=";
                "indexmap-2.2.4" = "sha256-uG8XMuoFt79cCZ8kqundQs++rqDLC/0ppiWToeAk5BE=";
                "ledger-namada-rs-0.0.1" = "sha256-qFL8LU7i5NAnMUhtrGykVfiYX1NodCNkZG07twyVrac=";
                "librocksdb-sys-0.16.0+8.10.0" = "sha256-ZcX2bpTDprcefo1ziyQ58GggX2D7NH17/zYvpbGSvhk=";
                "masp_note_encryption-1.0.0" = "sha256-6oYRYxUIg5bQa4f8IO3bq638GJpmR6N3EzaVTqbA3zs=";
                "num-traits-0.2.19" = "sha256-j6DT5w07A2qBfwojNA3y1eZNP6+BV4A+SRWbtFXLuXo=";
                "reddsa-0.5.1" = "sha256-uOJvanjyUEcMoEgDGaseXXbl5KpvYcyyfQfkVA4KipM=";
                "smooth-operator-0.7.0" = "sha256-OOA0WotkqTtnU3dIunvrDE41pwCOiqpFhNT7uZn+SPw=";
                "sparse-merkle-tree-0.3.1-pre" = "sha256-ckgX6XQj1TMRdDHC8P/jy5Mt0l1hnXdacE6jjViXJsE=";
                "tiny-bip39-0.8.2" = "sha256-TU+7Vug3+M6Zxhy6Wln54Pxc9ES4EdFq5TvMOcAG+qA=";
                "tiny-hderive-0.3.0" = "sha256-75D7h8S1/bMTlh3hq8YBAcgyzYBwBOvU249VdzQsICI=";
                "zcash_encoding-0.2.0" = "sha256-keuaoM/t1Q/+8JMemMMUuIo4g5I/EAoONFge+dyWGy0=";
              };
            };

            nativeBuildInputs = myNativeBuildInputs ++ (if builtins.hasAttr "extraNativeBuildInputs" attrs
                                                        then attrs.extraNativeBuildInputs
                                                        else []);
            buildInputs = myBuildInputs ++ (if builtins.hasAttr "extraBuildInputs" attrs
                                            then attrs.extraBuildInputs
                                            else []);

            RUST_BACKTRACE = 1;
            RUSTUP_TOOLCHAIN = rust.version;
            LIBCLANG_PATH = "${libclang.lib}/lib";

            preBuild = ''
              # From: https://github.com/NixOS/nixpkgs/blob/1fab95f5190d087e66a3502481e34e15d62090aa/pkgs/applications/networking/browsers/firefox/common.nix#L247-L253
              # Set C flags for Rust's bindgen program.
              # Unlike ordinary C compilation, bindgen does not invoke $CC directly.
              # Instead it uses LLVM's libclang.
              # To make sure all necessary flags are included we need to look in a few places.
              export BINDGEN_EXTRA_CLANG_ARGS="\
                $(< ${stdenv.cc}/nix-support/libc-crt1-cflags) \
                $(< ${stdenv.cc}/nix-support/libc-cflags) \
                $(< ${stdenv.cc}/nix-support/cc-cflags) \
                $(< ${stdenv.cc}/nix-support/libcxx-cxxflags) \
                ${lib.optionalString stdenv.cc.isClang "-idirafter ${stdenv.cc.cc}/lib/clang/${lib.getVersion stdenv.cc.cc}/include"} \
                ${lib.optionalString stdenv.cc.isGNU "-isystem ${stdenv.cc.cc}/include/c++/${lib.getVersion stdenv.cc.cc} -isystem ${stdenv.cc.cc}/include/c++/${lib.getVersion stdenv.cc.cc}/${stdenv.hostPlatform.config} -idirafter ${stdenv.cc.cc}/lib/gcc/${stdenv.hostPlatform.config}/${lib.getVersion stdenv.cc.cc}/include"} \
              "
            '';

            # disable tests
            doCheck = false;
          }
          // attrs);
    in rec {
      packages = with pkgs; rec {
        cometbft = buildGoModule rec {
          name = "cometbft";
          version = "0.38.7";

          src = fetchFromGitHub {
            owner = "cometbft";
            repo = "cometbft";
            rev = "v${version}";
            sha256 = "sha256-YDk9Xcv+R1RoS1KWqlhJoTGs7p3sNxguGmnlP8D5peg=";
          };
          vendorHash = "sha256-Z6Rzc3fMX2F/4jep/u1x/qAkfIKioq9L7jxmlbuFskQ=";

          doCheck = false;
        };

        namada = myBuildRustPackage rec {
          pname = "namada";
          buildAndTestSubdir = ".";
          extraBuildInputs = [ cometbft ];

          postFixup = ''
            wrapProgram $out/bin/namada --prefix PATH : ${lib.makeBinPath [ cometbft ]}
            wrapProgram $out/bin/namadac --prefix PATH : ${lib.makeBinPath [ cometbft ]}
            wrapProgram $out/bin/namadan --prefix PATH : ${lib.makeBinPath [ cometbft ]}
            wrapProgram $out/bin/namadar --prefix PATH : ${lib.makeBinPath [ cometbft ]}
            wrapProgram $out/bin/namadaw --prefix PATH : ${lib.makeBinPath [ cometbft ]}
          '';
        };

        default = namada;
      };

      apps = rec {
        namada = utils.lib.mkApp {
          drv = packages.namada;
          exePath = "/bin/namada";
        };

        default = namada;
      };
    });
}
