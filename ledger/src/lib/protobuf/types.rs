#[derive(Hash, Clone, PartialEq, ::prost::Message)]
pub struct Intent {
    /// google.protobuf.Timestamp timestamp = 2;
    #[prost(string, tag = "1")]
    pub data: ::prost::alloc::string::String,
}
#[derive(Hash, Clone, PartialEq, ::prost::Message)]
pub struct DkgMessage {
    #[prost(string, tag = "1")]
    pub data: ::prost::alloc::string::String,
}
#[derive(Hash, Clone, PartialEq, ::prost::Message)]
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
