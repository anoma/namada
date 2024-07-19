use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

use borsh::schema::{add_definition, Declaration, Definition, Fields};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXUPPER;
use ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use ibc::apps::nft_transfer::types::{
    ClassData, ClassId, ClassUri, Data, Memo as NftMemo, PrefixedClassId,
    TokenData, TokenId, TokenIds, TokenUri, TracePath, TracePrefix,
    PORT_ID_STR as NFT_PORT_ID_STR,
};
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use ibc::apps::transfer::types::packet::PacketData;
use ibc::apps::transfer::types::{
    Amount, BaseDenom, Memo, PrefixedCoin, PrefixedDenom,
    PORT_ID_STR as FT_PORT_ID_STR,
};
use ibc::core::channel::types::msgs::PacketMsg;
use ibc::core::channel::types::packet::Packet;
use ibc::core::channel::types::timeout::TimeoutHeight;
use ibc::core::client::types::Height;
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::core::host::types::identifiers::{ChannelId, PortId};
use ibc::core::primitives::{Signer, Timestamp};
use masp_primitives::transaction::Transaction as MaspTransaction;
use namada_core::borsh::BorshSerializeExt;
use namada_token::Transfer;

/// Supports types that implement older Borsh versions
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BorshAdapter<T>(pub T);

impl<T> Deref for BorshAdapter<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for BorshAdapter<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> From<T> for BorshAdapter<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

/// The different variants of an Ibc message
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum IbcMessage {
    /// Ibc Envelop
    Envelope(Box<MsgEnvelope>),
    /// Ibc transaprent transfer
    Transfer(MsgTransfer),
    /// NFT transfer
    NftTransfer(MsgNftTransfer),
}

impl BorshSchema for IbcMessage {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        MsgTransfer::add_definitions_recursively(definitions);
        MsgNftTransfer::add_definitions_recursively(definitions);
        // Variants of the enumeration leaving out envelope
        let variants = vec![
            (1, "Transfer".to_string(), MsgTransfer::declaration()),
            (2, "NftTransfer".to_string(), MsgNftTransfer::declaration()),
        ];
        add_definition(
            Self::declaration(),
            Definition::Enum {
                tag_width: 1,
                variants,
            },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "IbcMessage".into()
    }
}

/// IBC transfer message with `Transfer`
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct MsgTransfer {
    /// IBC transfer message
    #[borsh(schema(with_funcs(
        declaration = "BorshAdapter::<IbcMsgTransfer>::declaration",
        definitions = "BorshAdapter::<IbcMsgTransfer>::add_definitions_recursively"
    ),))]
    pub message: IbcMsgTransfer,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<Transfer>,
}

impl BorshSchema for BorshAdapter<BaseDenom> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "BaseDenom".into()
    }
}

impl BorshSchema for BorshAdapter<PrefixedDenom> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        BorshAdapter::<TracePath>::add_definitions_recursively(definitions);
        BorshAdapter::<BaseDenom>::add_definitions_recursively(definitions);
        let fields = Fields::NamedFields(vec![
            (
                "trace_path".to_string(),
                BorshAdapter::<TracePath>::declaration(),
            ),
            (
                "base_denom".to_string(),
                BorshAdapter::<BaseDenom>::declaration(),
            ),
        ]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "PrefixedDenom".into()
    }
}

impl BorshSchema for BorshAdapter<Amount> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        add_definition(
            Self::declaration(),
            Definition::Primitive(32),
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "IbcAmount".into()
    }
}

impl BorshSchema for BorshAdapter<PrefixedCoin> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        BorshAdapter::<PrefixedDenom>::add_definitions_recursively(definitions);
        BorshAdapter::<Amount>::add_definitions_recursively(definitions);
        let fields = Fields::NamedFields(vec![
            (
                "denom".to_string(),
                BorshAdapter::<PrefixedDenom>::declaration(),
            ),
            ("amount".to_string(), BorshAdapter::<Amount>::declaration()),
        ]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "PrefixedCoin".into()
    }
}

impl BorshSchema for BorshAdapter<Memo> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "Memo".into()
    }
}

impl BorshSchema for BorshAdapter<PacketData> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        BorshAdapter::<PrefixedCoin>::add_definitions_recursively(definitions);
        BorshAdapter::<Signer>::add_definitions_recursively(definitions);
        BorshAdapter::<Memo>::add_definitions_recursively(definitions);
        let fields = Fields::NamedFields(vec![
            (
                "token".to_owned(),
                BorshAdapter::<PrefixedCoin>::declaration(),
            ),
            ("sender".to_owned(), BorshAdapter::<Signer>::declaration()),
            ("receiver".to_owned(), BorshAdapter::<Signer>::declaration()),
            ("memo".to_owned(), BorshAdapter::<Memo>::declaration()),
        ]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "PacketData".into()
    }
}

impl BorshSchema for BorshAdapter<IbcMsgTransfer> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        BorshAdapter::<PortId>::add_definitions_recursively(definitions);
        BorshAdapter::<ChannelId>::add_definitions_recursively(definitions);
        BorshAdapter::<PacketData>::add_definitions_recursively(definitions);
        BorshAdapter::<TimeoutHeight>::add_definitions_recursively(definitions);
        BorshAdapter::<Timestamp>::add_definitions_recursively(definitions);
        let fields = Fields::NamedFields(vec![
            (
                "port_id_on_a".to_owned(),
                BorshAdapter::<PortId>::declaration(),
            ),
            (
                "chan_id_on_a".to_owned(),
                BorshAdapter::<ChannelId>::declaration(),
            ),
            (
                "packet_data".to_owned(),
                BorshAdapter::<PacketData>::declaration(),
            ),
            (
                "timeout_height_on_b".to_owned(),
                BorshAdapter::<TimeoutHeight>::declaration(),
            ),
            (
                "timeout_timestamp_on_b".to_owned(),
                BorshAdapter::<Timestamp>::declaration(),
            ),
        ]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "IbcMsgTransfer".into()
    }
}

/// IBC NFT transfer message with `Transfer`
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct MsgNftTransfer {
    /// IBC NFT transfer message
    #[borsh(schema(with_funcs(
        declaration = "BorshAdapter::<IbcMsgNftTransfer>::declaration",
        definitions = "BorshAdapter::<IbcMsgNftTransfer>::add_definitions_recursively"
    ),))]
    pub message: IbcMsgNftTransfer,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<Transfer>,
}

impl BorshSchema for BorshAdapter<PortId> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "PortId".into()
    }
}

impl BorshSchema for BorshAdapter<ChannelId> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "ChannelId".into()
    }
}

impl BorshSchema for BorshAdapter<Signer> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "IbcSigner".into()
    }
}

impl BorshSchema for BorshAdapter<NftMemo> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "NftMemo".into()
    }
}

impl BorshSchema for BorshAdapter<ClassId> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "ClassId".into()
    }
}

impl BorshSchema for BorshAdapter<Data> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "IbcData".into()
    }
}

impl BorshSchema for BorshAdapter<TokenId> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "TokenId".into()
    }
}

impl BorshSchema for BorshAdapter<ClassUri> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "ClassUri".into()
    }
}

impl BorshSchema for BorshAdapter<TokenUri> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        String::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![String::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "TokenUri".into()
    }
}

impl BorshSchema for BorshAdapter<ClassData> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        BorshAdapter::<Data>::add_definitions_recursively(definitions);
        let fields =
            Fields::UnnamedFields(vec![BorshAdapter::<Data>::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "ClassData".into()
    }
}

impl BorshSchema for BorshAdapter<TokenData> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        BorshAdapter::<Data>::add_definitions_recursively(definitions);
        let fields =
            Fields::UnnamedFields(vec![BorshAdapter::<Data>::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "TokenData".into()
    }
}

impl BorshSchema for BorshAdapter<TracePath> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        Vec::<BorshAdapter<TracePrefix>>::add_definitions_recursively(
            definitions,
        );
        let fields = Fields::UnnamedFields(vec![Vec::<
            BorshAdapter<TracePrefix>,
        >::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "TracePath".into()
    }
}

impl BorshSchema for BorshAdapter<Height> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        u64::add_definitions_recursively(definitions);
        let fields = Fields::NamedFields(vec![
            ("revision_number".to_string(), u64::declaration()),
            ("revision_height".to_string(), u64::declaration()),
        ]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "Height".into()
    }
}

impl BorshSchema for BorshAdapter<TracePrefix> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        BorshAdapter::<PortId>::add_definitions_recursively(definitions);
        BorshAdapter::<ChannelId>::add_definitions_recursively(definitions);
        let fields = Fields::NamedFields(vec![
            ("port_id".to_string(), BorshAdapter::<PortId>::declaration()),
            (
                "channel_id".to_string(),
                BorshAdapter::<ChannelId>::declaration(),
            ),
        ]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "TracePrefix".into()
    }
}

impl BorshSchema for BorshAdapter<PrefixedClassId> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        BorshAdapter::<TracePath>::add_definitions_recursively(definitions);
        BorshAdapter::<ClassId>::add_definitions_recursively(definitions);
        let fields = Fields::NamedFields(vec![
            (
                "trace_path".to_string(),
                BorshAdapter::<TracePath>::declaration(),
            ),
            (
                "base_class_id".to_string(),
                BorshAdapter::<ClassId>::declaration(),
            ),
        ]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "PrefixedClassId".into()
    }
}

impl BorshSchema for BorshAdapter<TimeoutHeight> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        <()>::add_definitions_recursively(definitions);
        BorshAdapter::<Height>::add_definitions_recursively(definitions);
        let variants = vec![
            (0, "Never".to_string(), <()>::declaration()),
            (1, "At".to_string(), BorshAdapter::<Height>::declaration()),
        ];
        add_definition(
            Self::declaration(),
            Definition::Enum {
                tag_width: 1,
                variants,
            },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "TimeoutHeight".into()
    }
}

impl BorshSchema for BorshAdapter<Timestamp> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        u64::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![u64::declaration()]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "Timestamp".into()
    }
}

impl BorshSchema for BorshAdapter<TokenIds> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        Vec::<BorshAdapter<TokenId>>::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![
            Vec::<BorshAdapter<TokenId>>::declaration(),
        ]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "TokenIds".into()
    }
}

impl BorshSchema for BorshAdapter<NftPacketData> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        BorshAdapter::<PrefixedClassId>::add_definitions_recursively(
            definitions,
        );
        Option::<BorshAdapter<ClassUri>>::add_definitions_recursively(
            definitions,
        );
        Option::<BorshAdapter<ClassData>>::add_definitions_recursively(
            definitions,
        );
        BorshAdapter::<TokenIds>::add_definitions_recursively(definitions);
        Option::<Vec<BorshAdapter<TokenUri>>>::add_definitions_recursively(
            definitions,
        );
        Option::<Vec<BorshAdapter<TokenData>>>::add_definitions_recursively(
            definitions,
        );
        BorshAdapter::<Signer>::add_definitions_recursively(definitions);
        Option::<BorshAdapter<NftMemo>>::add_definitions_recursively(
            definitions,
        );
        let fields = Fields::NamedFields(vec![
            (
                "class_id".to_owned(),
                BorshAdapter::<PrefixedClassId>::declaration(),
            ),
            (
                "class_uri".to_owned(),
                Option::<BorshAdapter<ClassUri>>::declaration(),
            ),
            (
                "class_data".to_owned(),
                Option::<BorshAdapter<ClassData>>::declaration(),
            ),
            (
                "token_ids".to_owned(),
                BorshAdapter::<TokenIds>::declaration(),
            ),
            (
                "token_uris".to_owned(),
                Option::<Vec<BorshAdapter<TokenUri>>>::declaration(),
            ),
            (
                "token_data".to_owned(),
                Option::<Vec<BorshAdapter<TokenData>>>::declaration(),
            ),
            ("sender".to_owned(), BorshAdapter::<Signer>::declaration()),
            ("receiver".to_owned(), BorshAdapter::<Signer>::declaration()),
            (
                "memo".to_owned(),
                Option::<BorshAdapter<NftMemo>>::declaration(),
            ),
        ]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "NftPacketData".into()
    }
}

impl BorshSchema for BorshAdapter<IbcMsgNftTransfer> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        BorshAdapter::<PortId>::add_definitions_recursively(definitions);
        BorshAdapter::<ChannelId>::add_definitions_recursively(definitions);
        BorshAdapter::<NftPacketData>::add_definitions_recursively(definitions);
        BorshAdapter::<TimeoutHeight>::add_definitions_recursively(definitions);
        BorshAdapter::<Timestamp>::add_definitions_recursively(definitions);
        let fields = Fields::NamedFields(vec![
            (
                "port_id_on_a".to_owned(),
                BorshAdapter::<PortId>::declaration(),
            ),
            (
                "chan_id_on_a".to_owned(),
                BorshAdapter::<ChannelId>::declaration(),
            ),
            (
                "packet_data".to_owned(),
                BorshAdapter::<NftPacketData>::declaration(),
            ),
            (
                "timeout_height_on_b".to_owned(),
                BorshAdapter::<TimeoutHeight>::declaration(),
            ),
            (
                "timeout_timestamp_on_b".to_owned(),
                BorshAdapter::<Timestamp>::declaration(),
            ),
        ]);
        add_definition(
            Self::declaration(),
            Definition::Struct { fields },
            definitions,
        );
    }

    fn declaration() -> Declaration {
        "IbcMsgNftTransfer".into()
    }
}

/// Shielding data in IBC packet memo
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct IbcShieldingData {
    /// MASP transaction for receiving the token
    pub shielding: Option<MaspTransaction>,
    /// MASP transaction for refunding the token
    pub refund: Option<MaspTransaction>,
}

impl From<IbcShieldingData> for String {
    fn from(data: IbcShieldingData) -> Self {
        HEXUPPER.encode(&data.serialize_to_vec())
    }
}

/// Extract MASP transaction from IBC envelope
pub fn extract_masp_tx_from_envelope(
    envelope: &MsgEnvelope,
) -> Option<MaspTransaction> {
    match envelope {
        MsgEnvelope::Packet(packet_msg) => match packet_msg {
            PacketMsg::Recv(msg) => {
                extract_masp_tx_from_packet(&msg.packet, false)
            }
            PacketMsg::Ack(msg) => {
                extract_masp_tx_from_packet(&msg.packet, true)
            }
            PacketMsg::Timeout(msg) => {
                extract_masp_tx_from_packet(&msg.packet, true)
            }
            _ => None,
        },
        _ => None,
    }
}

/// Decode IBC shielding data from the string
pub fn decode_ibc_shielding_data(
    s: impl AsRef<str>,
) -> Option<IbcShieldingData> {
    let bytes = HEXUPPER.decode(s.as_ref().as_bytes()).ok()?;
    IbcShieldingData::try_from_slice(&bytes).ok()
}

/// Extract MASP transaction from IBC packet memo
pub fn extract_masp_tx_from_packet(
    packet: &Packet,
    is_sender: bool,
) -> Option<MaspTransaction> {
    let port_id = if is_sender {
        &packet.port_id_on_a
    } else {
        &packet.port_id_on_b
    };
    let memo = extract_memo_from_packet(packet, port_id)?;
    let shielding_data = decode_ibc_shielding_data(memo)?;
    if is_sender {
        shielding_data.refund
    } else {
        shielding_data.shielding
    }
}

fn extract_memo_from_packet(
    packet: &Packet,
    port_id: &PortId,
) -> Option<String> {
    match port_id.as_str() {
        FT_PORT_ID_STR => {
            let packet_data =
                serde_json::from_slice::<PacketData>(&packet.data).ok()?;
            if packet_data.memo.as_ref().is_empty() {
                None
            } else {
                Some(packet_data.memo.as_ref().to_string())
            }
        }
        NFT_PORT_ID_STR => {
            let packet_data =
                serde_json::from_slice::<NftPacketData>(&packet.data).ok()?;
            Some(packet_data.memo?.as_ref().to_string())
        }
        _ => {
            tracing::warn!(
                "Memo couldn't be extracted from the unsupported IBC packet \
                 data for Port ID {port_id}"
            );
            None
        }
    }
}

/// Get IBC memo string from MASP transaction for receiving
pub fn convert_masp_tx_to_ibc_memo(transaction: &MaspTransaction) -> String {
    let shielding_data = IbcShieldingData {
        shielding: Some(transaction.clone()),
        refund: None,
    };
    shielding_data.into()
}
