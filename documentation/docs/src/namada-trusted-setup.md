# Namada Trusted Setup

The Namada Trusted Setup Ceremony generates the public parameters for the Multi-Asset Shielded Pool (MASP) circuit and guarantees its security. Under the hood, a trusted setup ceremony is a Multi-Party Computation (MPC) that lets many participants contribute randomness to the public parameters in a trustless manner. The setup is secure, as long as one participant is honest.

## Participate in Namada Trusted Setup
If you are interested in participating in the ceremony head over to the [Namada website](https://namada.net/trusted-setup.html) to be notified about the launch.

To contribute during the ceremony, you can install and use the canonical client implementation below. It computes the parameters for the MASP and communicates with the ceremony's coordinator. Also, check out the [Contribution Flow](#contribution-flow).

### Building and contributing from source

Via command-line, [install Rust](https://www.rust-lang.org/tools/install) by entering the following command:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

If you already have Rust installed, make sure it is the most up-to-date version updated:
```
rustup update
```

Once Rust is installed, clone the [Namada Trusted Setup Ceremony](https://github.com/anoma/namada-trusted-setup) GitHub repository and change directories into `namada-setup-ceremony`:
```
git clone https://github.com/anoma/namada-trusted-setup.git
cd namada-trusted-setup
```

Build the binaries and start your contribution with:
```
cargo run --release --bin phase1 --features cli contribute https://contribute.namada.net
```

### Contribution Flow

To enforce security, the Namada Trusted Setup accepts as many diverse contributions as possible: anonymous contributions, original source of randomness, alternative client, computation of the parameters on an airgapped or offline machine.

That's why the client gives you the choice of multiple options during your contribution.

The canonical client follows these steps:
1. It generates a BIP39 24 words mnemonic that serves as a seed for your `ed25519` key pair. Keep it safely! It's the only way to generate your key pair and claim your rewards if you participate in the incentivized program.
2. You will be asked if you want to participate in the incentivized program. If you want to participate, you will need to provide your legal name and a real email address so you can be contacted in the future for a KYC. The other option is to contribute anonymously.
3. If you agreed to the previous question, you will be asked if you want to participate in the creative contest. If you agree, you will be contacted after the ceremony by email to prove your creative contribution.
4. You will join the ceremony's queue.
5. When it is your turn, the challenge file will be downloaded and you will be asked if you want to contribute on an offline machine or not and if you want to give your own 32 bytes seed of randomness or simply use the default method to generate randomness.
6. If you chose to pursue on the same machine, the client will start contributing and when done it will upload the file to the server.
7. That's all! Thanks for your contribution. 

