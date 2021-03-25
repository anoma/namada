use std::error::Error;

use anoma::protobuf::types::IntentMessage;
use anoma::{bookkeeper::Bookkeeper, config::Config};
use libp2p::gossipsub::{IdentTopic as Topic, MessageAcceptance};
use libp2p::identity::Keypair;
use libp2p::identity::Keypair::Ed25519;
use libp2p::PeerId;
use prost::Message;
use tokio::sync::mpsc::Receiver;

use super::dkg::DKG;
use super::network_behaviour::Behaviour;
use super::orderbook::{self, Orderbook};
use super::types::NetworkEvent;

pub type Swarm = libp2p::Swarm<Behaviour>;
pub fn build_swarm(
    bookkeeper: Bookkeeper,
) -> Result<(Swarm, Receiver<NetworkEvent>), Box<dyn Error>> {
    // Create a random PeerId
    let local_key: Keypair = Ed25519(bookkeeper.key);
    let local_peer_id: PeerId = PeerId::from(local_key.public());

    // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
    let transport = libp2p::build_development_transport(local_key.clone())?;

    let (gossipsub, network_event_receiver) = Behaviour::new(local_key);

    Ok((
        Swarm::new(transport, gossipsub, local_peer_id),
        network_event_receiver,
    ))
}

pub fn prepare_swarm(swarm: &mut Swarm, config: Config) {
    for topic_string in config.p2p.topics.clone() {
        let topic = Topic::new(topic_string);
        swarm.gossipsub.subscribe(&topic).unwrap();
    }

    // Listen on all interfaces and whatever port the OS assigns
    Swarm::listen_on(swarm, config.p2p.get_address().parse().unwrap()).unwrap();

    // Reach out to another node if specified
    for to_dial in config.p2p.peers.clone() {
        let dialing = to_dial.clone();
        match to_dial.parse() {
            Ok(to_dial) => match Swarm::dial_addr(swarm, to_dial) {
                Ok(_) => println!("Dialed {:?}", dialing),
                Err(e) => {
                    println!("Dial {:?} failed: {:?}", dialing, e)
                }
            },
            Err(err) => {
                println!("Failed to parse address to dial: {:?}", err)
            }
        }
    }
}

#[tokio::main]
pub async fn dispatcher(
    mut swarm: Swarm,
    mut network_event_receiver: Receiver<NetworkEvent>,
    rpc_event_receiver: Option<Receiver<IntentMessage>>,
    orderbook_node: Option<Orderbook>,
    dkg_node: Option<DKG>,
) -> Result<(), Box<dyn Error>> {
    if orderbook_node.is_none() && dkg_node.is_none() {
        panic!("Need at least one module to be active, orderbook or dkg")
    }
    // Here it should pass the option value to handle_network_event instead of
    // unwraping it
    let mut orderbook_node: Orderbook = orderbook_node.unwrap();
    let mut dkg_node = dkg_node.unwrap();
    match rpc_event_receiver {
        Some(mut rpc_event_receiver) => {
            loop {
                tokio::select! {
                    event = rpc_event_receiver.recv() =>
                    {handle_rpc_event(event,&mut swarm)}
                    swarm_event = swarm.next() => {
                        // All events are handled by the
                        // `NetworkBehaviourEventProcess`es.  I.e. the
                        // `swarm.next()` future drives the `Swarm` without ever
                        // terminating.
                        panic!("Unexpected event: {:?}", swarm_event);
                    }
                    event = network_event_receiver.recv() => {
                        handle_network_event(event, &mut orderbook_node, &mut dkg_node, &mut swarm)?
                    }
                };
            }
        }
        None => {
            loop {
                tokio::select! {
                    swarm_event = swarm.next() => {
                        // All events are handled by the
                        // `NetworkBehaviourEventProcess`es.  I.e. the
                        // `swarm.next()` future drives the `Swarm` without ever
                        // terminating.
                        panic!("Unexpected event: {:?}", swarm_event);
                    }
                    event = network_event_receiver.recv() => {
                        handle_network_event(event, &mut orderbook_node, &mut dkg_node, &mut swarm)?
                    }
                }
            }
        }
    }
}

fn handle_rpc_event(event: Option<IntentMessage>, swarm: &mut Swarm) {
    if let Some(event) = event {
        println!("received {:?} from a client", event);
        if let IntentMessage { intent: Some(i) } = event {
            let mut tix_bytes = vec![];
            i.encode(&mut tix_bytes).unwrap();
            let _message_id = swarm.gossipsub.publish(
                Topic::from(super::types::Topic::Orderbook),
                tix_bytes,
            );
        }
    }
}
fn handle_network_event(
    event: Option<NetworkEvent>,
    orderbook_node: &mut Orderbook,
    _dkg_node: &mut DKG,
    swarm: &mut Swarm,
) -> orderbook::Result<()> {
    if let Some(event) = event {
        println!("received {:?} from the network", event);
        match event {
            NetworkEvent::Message(msg)
                if msg.topic == super::types::Topic::Orderbook =>
            {
                if orderbook_node.apply(&msg)? {
                    {
                        swarm
                            .gossipsub
                            .report_message_validation_result(
                                &msg.message_id,
                                &msg.peer,
                                MessageAcceptance::Accept,
                            )
                            .unwrap();
                    }
                }
            }
            NetworkEvent::Message(msg) => {
                panic!("topic {:?} not yet implemented", msg.topic)
            }
        }
    }
    Ok(())
}
