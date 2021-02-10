//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use anoma::Message;
use anoma::Transaction;

use clap::Clap;
use tendermint_rpc::{Client, HttpClient};

/// Anoma client
#[derive(Clap)]
#[clap(version = "1.0", author = "Heliax <TODO@heliax.dev>")]
enum Opts {
    /// Transfer
    Transfer(Transfer),
}

/// A subcommand for controlling trasfers
#[derive(Clap)]
struct Transfer {
    /// An example command
    #[clap(short)]
    count: u64,
}

pub async fn main() {
    match Opts::parse() {
        Opts::Transfer(Transfer { count }) => transfer(count).await,
    }
}

async fn transfer(count: u64) {
    let tx = Transaction { count };
    let mut tx_bytes = vec![];
    tx.encode(&mut tx_bytes).unwrap();
    // let tx_param = hex::encode(tx_bytes);
    let client = HttpClient::new("tcp://127.0.0.1:26657".parse().unwrap()).unwrap();
    let response = client
        .broadcast_tx_commit(tx_bytes.into())
        .await;
    println!("{:#?}", response);
}
