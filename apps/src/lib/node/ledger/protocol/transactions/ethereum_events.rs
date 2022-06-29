use anoma::types::ethereum_events::MultiSignedEthEvent;

#[derive(Debug, PartialEq, Eq)]
pub struct EthMsg;

pub(crate) fn calculate_eth_msgs_state(
    _events: Vec<MultiSignedEthEvent>,
) -> Vec<EthMsg> {
    vec![]
}

#[cfg(test)]
mod test {
    use super::calculate_eth_msgs_state;

    #[test]
    fn test_calculate_eth_msgs_state() {
        assert_eq!(calculate_eth_msgs_state(vec![]), vec![]);
    }
}
