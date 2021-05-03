//! Temporary helper until we have a proper wallet.

use anoma_shared::types::key::ed25519::{Keypair, PublicKey};

pub fn ada_keypair() -> Keypair {
    // generated from [`tests::temp_gen_keypair`]
    let bytes = [
        115, 191, 32, 247, 18, 101, 5, 106, 26, 203, 48, 145, 39, 41, 41, 196,
        252, 190, 245, 222, 96, 209, 34, 36, 40, 214, 169, 156, 235, 78, 188,
        33, 165, 114, 129, 225, 221, 159, 211, 158, 195, 232, 161, 98, 161,
        100, 60, 167, 200, 54, 192, 242, 218, 227, 190, 241, 65, 42, 58, 97,
        162, 253, 225, 167,
    ];
    Keypair::from_bytes(&bytes).unwrap()
}

pub fn alan_keypair() -> Keypair {
    // generated from [`tests::temp_gen_keypair`]
    let bytes = [
        240, 3, 224, 69, 201, 148, 60, 53, 112, 79, 80, 107, 101, 127, 186, 6,
        176, 162, 113, 224, 62, 8, 183, 187, 124, 234, 244, 251, 92, 36, 119,
        243, 87, 37, 18, 169, 91, 25, 13, 97, 91, 25, 135, 247, 7, 37, 114,
        166, 73, 81, 173, 80, 244, 249, 126, 249, 219, 184, 53, 69, 196, 106,
        230, 0,
    ];
    Keypair::from_bytes(&bytes).unwrap()
}

pub fn matchmaker_keypair() -> Keypair {
    // generated from [`tests::temp_gen_keypair`]
    let bytes = [
        91, 67, 244, 37, 241, 33, 157, 218, 37, 172, 191, 122, 75, 2, 44, 219,
        28, 123, 44, 34, 9, 240, 244, 49, 112, 192, 180, 98, 142, 160, 182, 14,
        244, 254, 3, 176, 211, 19, 15, 7, 126, 77, 81, 204, 119, 72, 186, 172,
        153, 135, 80, 71, 107, 239, 153, 74, 10, 115, 172, 78, 125, 24, 49,
        104,
    ];
    Keypair::from_bytes(&bytes).unwrap()
}

pub fn ada_pk() -> PublicKey {
    PublicKey::from(ada_keypair().public)
}

pub fn alan_pk() -> PublicKey {
    PublicKey::from(alan_keypair().public)
}

pub fn matchmaker_pk() -> PublicKey {
    PublicKey::from(matchmaker_keypair().public)
}

pub fn key_of(name: impl AsRef<str>) -> Keypair {
    match name.as_ref() {
        "ada" => ada_keypair(),
        "alan" => alan_keypair(),
        "matchmaker" => matchmaker_keypair(),
        other => {
            panic!("Dont' have keys for: {}", other)
        }
    }
}

#[cfg(test)]
mod tests {
    use anoma_shared::types::key::ed25519::Keypair;
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    /// Run `cargo test temp_gen_keypair -- --nocapture` to generate a keypair.
    #[test]
    fn temp_gen_keypair() {
        let mut rng: ThreadRng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        println!("keypair {:?}", keypair.to_bytes());
    }
}
