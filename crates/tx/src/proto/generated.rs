#![allow(missing_docs)]

/// Tonic tx types generated from protobuf definitions at build
pub mod types {
    include!(concat!(env!("OUT_DIR"), "/types.rs"));
}
