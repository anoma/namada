//! Hardware wallet transport over HID or TCP

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::Deref;
use std::str::FromStr;

use ledger_lib::Transport;
use ledger_lib::transport::TcpInfo;
use ledger_transport::{APDUAnswer, APDUCommand};
use ledger_transport_hid::TransportNativeHID;
use ledger_transport_hid::hidapi::HidApi;
use namada_sdk::args;

/// Hardware wallet transport
pub enum WalletTransport {
    /// HID transport
    HID(TransportNativeHID),
    /// TCP transport
    TCP(TransportTcp),
}

impl WalletTransport {
    pub fn from_arg(arg: args::DeviceTransport) -> Self {
        match arg {
            args::DeviceTransport::Hid => {
                let hidapi = HidApi::new()
                    .expect("Must be able to instantiate a hidapi context");
                let transport = TransportNativeHID::new(&hidapi)
                    .expect("Must be able to connect to a HID wallet");
                Self::HID(transport)
            }
            args::DeviceTransport::Tcp => Self::TCP(TransportTcp),
        }
    }
}

#[ledger_transport::async_trait]
impl ledger_transport::Exchange for WalletTransport {
    type AnswerType = Vec<u8>;
    type Error = std::io::Error;

    async fn exchange<I>(
        &self,
        command: &APDUCommand<I>,
    ) -> Result<APDUAnswer<Self::AnswerType>, Self::Error>
    where
        I: Deref<Target = [u8]> + Send + Sync,
    {
        match self {
            WalletTransport::HID(transport) => {
                transport.exchange(command).map_err(std::io::Error::other)
            }
            WalletTransport::TCP(transport) => transport
                .exchange(command)
                .await
                .map_err(std::io::Error::other),
        }
    }
}

/// Hardware wallet TCP transport
#[derive(Default)]
pub struct TransportTcp;

#[ledger_transport::async_trait]
impl ledger_transport::Exchange for TransportTcp {
    type AnswerType = Vec<u8>;
    type Error = ledger_lib::Error;

    async fn exchange<I>(
        &self,
        command: &APDUCommand<I>,
    ) -> Result<APDUAnswer<Self::AnswerType>, Self::Error>
    where
        I: Deref<Target = [u8]> + Send + Sync,
    {
        use ledger_lib::Exchange;
        let mut transport = ledger_lib::transport::TcpTransport::default();
        let ip = std::env::var("LEDGER_PROXY_ADDRESS")
            .map(|s| Ipv4Addr::from_str(&s).unwrap())
            .unwrap_or(Ipv4Addr::LOCALHOST);
        let port = std::env::var("LEDGER_PROXY_PORT")
            .map(|s| u16::from_str(&s).unwrap())
            .unwrap_or(9999);
        let mut device = transport
            .connect(TcpInfo {
                addr: SocketAddr::V4(SocketAddrV4::new(ip, port)),
            })
            .await?;
        let res = device
            .exchange(&command.serialize(), std::time::Duration::from_secs(60))
            .await?;
        Ok(APDUAnswer::from_answer(res).unwrap())
    }
}
