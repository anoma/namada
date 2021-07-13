use std::collections::VecDeque;

use anoma_vm_env::matchmaker_prelude::intent::{
    Exchange, FungibleTokenIntent, IntentTransfers,
};
use anoma_vm_env::matchmaker_prelude::key::ed25519::Signed;
use anoma_vm_env::matchmaker_prelude::*;
use petgraph::graph::{node_index, DiGraph, NodeIndex};
use petgraph::visit::{depth_first_search, Control, DfsEvent};
use petgraph::Graph;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExchangeNode {
    id: Vec<u8>,
    exchange: Exchange,
}

#[matchmaker]
fn add_intent(graph_bytes: Vec<u8>, id: Vec<u8>, data: Vec<u8>) -> bool {
    let intent = decode_intent_data(&data);
    let exchanges = intent.exchange.clone();
    let mut graph = decode_graph(graph_bytes);
    log_string(format!("trying to match intent: {:#?}", intent));
    exchanges.map(|exchange| add_node(&mut graph, id, exchange));
    find_match_and_remove_node(&mut graph);
    update_graph_data(&graph);
    true
}

fn create_transfer(
    from_node: &ExchangeNode,
    to_node: &ExchangeNode,
) -> token::Transfer {
    token::Transfer {
        source: from_node.exchange.addr.clone(),
        target: to_node.exchange.addr.clone(),
        token: to_node.exchange.token_buy.clone(),
        amount: to_node.exchange.amount_buy,
    }
}

fn send_tx(tx_data: IntentTransfers) {
    let tx_data_bytes = tx_data.try_to_vec().unwrap();
    send_match(tx_data_bytes);
}

fn decode_intent_data(bytes: &[u8]) -> FungibleTokenIntent {
    FungibleTokenIntent::try_from_slice(bytes).unwrap()
}

fn decode_graph(bytes: Vec<u8>) -> DiGraph<ExchangeNode, Address> {
    if bytes.is_empty() {
        Graph::new()
    } else {
        serde_json::from_slice(&bytes[..]).expect("error in json format")
    }
}

fn update_graph_data(graph: &DiGraph<ExchangeNode, Address>) {
    update_data(serde_json::to_vec(graph).unwrap());
}

// sell at max 100 BTC at 1.5 rate to buy 50 ETH --> 1BTC = 1,5ETH --> 1ETH =
// 1BTC/1,5 sell at max 100 ETH at 0,5 rate to buy 6 BTC
// do we ready need max_sell?

fn find_to_update_node(
    graph: &DiGraph<ExchangeNode, Address>,
    new_node: &ExchangeNode,
) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
    let start = node_index(0);
    let mut connect_sell = Vec::new();
    let mut connect_buy = Vec::new();
    depth_first_search(graph, Some(start), |event| {
        if let DfsEvent::Discover(index, _time) = event {
            let inverse_rate = 1. / new_node.exchange.rate_min;
            let current_node = &graph[index];
            if new_node.exchange.token_sell == current_node.exchange.token_buy
                && new_node.exchange.max_sell
                    <= current_node.exchange.amount_buy
                && inverse_rate >= current_node.rate_min
            {
                connect_sell.push(index);
            } else if new_node.exchange.token_buy
                == current_node.exchange.token_sell
                && new_node.exchange.amount_buy
                    <= current_node.exchange.max_sell
                && inverse_rate <= current_node.rate_min
            {
                connect_buy.push(index);
            }
        }
        Control::<()>::Continue
    });
    (connect_sell, connect_buy)
}

fn add_node(
    graph: &mut DiGraph<ExchangeNode, Address>,
    id: Vec<u8>,
    exchange: Exchange,
) {
    let new_node = ExchangeNode { id, exchange };
    let new_node_index = graph.add_node(new_node.clone());
    let (connect_sell, connect_buy) = find_to_update_node(&graph, &new_node);
    let sell_edge = new_node.exchange.token_sell;
    let buy_edge = new_node.exchange.token_buy;
    for node_index in connect_sell {
        graph.update_edge(new_node_index, node_index, sell_edge.clone());
    }
    for node_index in connect_buy {
        graph.update_edge(node_index, new_node_index, buy_edge.clone());
    }
}

fn create_and_send_tx_data(
    graph: &DiGraph<ExchangeNode, Address>,
    cycle_intents: Vec<NodeIndex>,
) {
    log_string(format!(
        "found match; creating tx with {:?} nodes",
        cycle_intents.len()
    ));
    let cycle_intents = sort_cycle(graph, cycle_intents);
    let mut cycle_intents_iter = cycle_intents.into_iter();
    let first_node = cycle_intents_iter.next().map(|i| &graph[i]).unwrap();
    let mut tx_data = IntentTransfers::empty();
    let last_node =
        cycle_intents_iter.fold(first_node, |prev_node, intent_index| {
            let node = &graph[intent_index];
            tx_data.transfers.insert(create_transfer(node, prev_node));
            tx_data
                .intents
                .insert(node.exchange.addr.clone(), node.exchange.clone());
            &node
        });
    tx_data
        .transfers
        .insert(create_transfer(first_node, last_node));
    tx_data.intents.insert(
        first_node.exchange.addr.clone(),
        first_node.exchange.clone(),
    );
    send_tx(tx_data)
}

// The cycle returned by tarjan_scc only contains the node_index in an arbitrary
// order without edges. we must reorder them to craft the transfer
fn sort_cycle(
    graph: &DiGraph<ExchangeNode, Address>,
    cycle_intents: Vec<NodeIndex>,
) -> Vec<NodeIndex> {
    let mut cycle_ordered = Vec::new();
    let mut cycle_intents = VecDeque::from(cycle_intents);
    let mut to_connect_node = cycle_intents.pop_front().unwrap();
    cycle_ordered.push(to_connect_node);
    while !cycle_intents.is_empty() {
        let pop_node = cycle_intents.pop_front().unwrap();
        if graph.contains_edge(to_connect_node, pop_node) {
            cycle_ordered.push(pop_node);
            to_connect_node = pop_node;
        } else {
            cycle_intents.push_back(pop_node);
        }
    }
    cycle_ordered.reverse();
    cycle_ordered
}

fn find_match_and_send_tx(
    graph: &DiGraph<ExchangeNode, Address>,
) -> Vec<NodeIndex> {
    let mut to_remove_nodes = Vec::new();
    for cycle_intents in petgraph::algo::tarjan_scc(&graph) {
        // a node is a cycle with itself
        if cycle_intents.len() > 1 {
            to_remove_nodes.extend(&cycle_intents);
            create_and_send_tx_data(graph, cycle_intents);
        }
    }
    to_remove_nodes
}

fn find_match_and_remove_node(graph: &mut DiGraph<ExchangeNode, Address>) {
    let mut to_remove_nodes = find_match_and_send_tx(&graph);
    // Must be sorted in reverse order because it removes the node by index
    // otherwise it would not remove the correct node
    to_remove_nodes.sort_by(|a, b| b.cmp(a));
    to_remove_nodes.into_iter().for_each(|i| {
        graph.remove_node(i);
    });
}
