#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Intent {
    #[prost(bytes = "vec", tag = "1")]
    pub data: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub timestamp: ::core::option::Option<::prost_types::Timestamp>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Tx {
    #[prost(bytes = "vec", tag = "1")]
    pub code: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub data: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DkgMessage {
    #[prost(string, tag = "1")]
    pub data: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IntentMessage {
    #[prost(message, optional, tag = "4")]
    pub intent: ::core::option::Option<Intent>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Message {
    #[prost(oneof = "message::Message", tags = "1, 2")]
    pub message: ::core::option::Option<message::Message>,
}
/// Nested message and enum types in `Message`.
pub mod message {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Message {
        #[prost(message, tag = "1")]
        IntentMessage(super::IntentMessage),
        #[prost(message, tag = "2")]
        DkgMsg(super::DkgMessage),
    }
}
