mod dkg;
mod mempool;
mod network_behaviour;
mod orderbook;
mod p2p;
mod types;

use std::thread;

// use self::Dkg::DKG;
use anoma::{self, config::Config};
use tokio::sync::mpsc;

use self::dkg::DKG;
use self::orderbook::Orderbook;
use crate::rpc;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Bad Bookkeeper file")]
    BadBookkeeper(),
    #[error("Error p2p swarm {0}")]
    P2pSwarmError(String),
    #[error("Error p2p dispatcher {0}")]
    P2pDispatcherError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn run(
    config: Config,
    rpc: bool,
    local_address: Option<String>,
    peers: Option<Vec<String>>,
    topics: Option<Vec<String>>,
) -> Result<()> {
    let bookkeeper = config
        .get_bookkeeper()
        .or_else(|_| Err(Error::BadBookkeeper()))?;

    let rpc_event_receiver = if rpc {
        let (tx, rx) = mpsc::channel(100);
        thread::spawn(|| rpc::rpc_server(tx).unwrap());
        Some(rx)
    } else {
        None
    };

    let p2p_local_address = local_address.unwrap_or(config.p2p.get_address());
    let p2p_peers = peers.unwrap_or(config.p2p.peers);
    let p2p_topics = topics.unwrap_or(config.p2p.topics);

    let (mut swarm, event_receiver) = p2p::build_swarm(bookkeeper)
        // .expect("msg");
        .map_err(|e| Error::P2pSwarmError(e.to_string()))?;
    p2p::prepare_swarm(&mut swarm, p2p_local_address, p2p_topics, p2p_peers);
    p2p::dispatcher(
        swarm,
        event_receiver,
        rpc_event_receiver,
        Some(Orderbook::new()),
        Some(DKG::new()),
    )
    .map_err(|e| Error::P2pDispatcherError(e.to_string()))?;
    Ok(())
}
