#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Tx {
    #[prost(bytes = "vec", tag = "1")]
    pub code: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub data: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Intent {
    #[prost(bytes = "vec", tag = "1")]
    pub data: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub timestamp: ::core::option::Option<::prost_types::Timestamp>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Filter {
    #[prost(bytes = "vec", tag = "1")]
    pub code: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DkgMessage {
    #[prost(string, tag = "1")]
    pub data: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IntentBroadcasterMessage {
    #[prost(oneof = "intent_broadcaster_message::Message", tags = "1, 2, 3")]
    pub message: ::core::option::Option<intent_broadcaster_message::Message>,
}
/// Nested message and enum types in `IntentBroadcasterMessage`.
pub mod intent_broadcaster_message {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Message {
        #[prost(message, tag = "1")]
        Intent(super::Intent),
        #[prost(message, tag = "2")]
        Filter(super::Filter),
        #[prost(message, tag = "3")]
        Dkg(super::DkgMessage),
    }
}
