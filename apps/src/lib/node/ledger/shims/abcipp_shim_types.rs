use tower_abci::{response, split, BoxError, Request, Response, Server};

pub mod shim {
    use std::convert::{TryFrom, TryInto};
    use tendermint_proto::abci::{RequestInitChain};
    use thiserror;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Error converting Request from ABCI to ABCI++: {:?}")]
        Convert(super::Request),
    }

    pub enum Request {
        InitChain(RequestInitChain),
        PrepareProposal(request::PrepareProposal),
        VerifyHeader,
        ProcessProposal,
        RevertProposal,
        FinalizeBlock(request::FinalizeBlock),
    }

    impl TryFrom<super::Request> for Request {
        type Error = Error;

        fn try_from(req: super::Request) -> Result<Self, Self::Error> {
            match req {
                super::Request::InitChain(inner) => Ok(Request::InitChain(inner)),

                _ => Err(Error::Convert())
            }
        }
    }

    pub enum Response {
        PrepareProposal(response::PrepareProposal),
        VerifyHeader(response::VerifyHeader),
        ProcessProposal(response::ProcessProposal),
        RevertProposal(response::RevertProposal),
        FinalizeBlock(response::FinalizeBlock),
    }

    pub mod request {
        use anoma_shared::types::storage::{BlockHash, BlockHeight};
        use tendermint_proto::types::Header;
        use tendermint_proto::abci::{RequestBeginBlock};

        pub struct PrepareProposal {
            pub hash: Vec<u8>,
            pub header: Option<Header>,
        }

        impl From<RequestBeginBlock> for PrepareProposal {
            fn from(block: RequestBeginBlock) -> Self {
                PrepareProposal {
                    hash: block.hash,
                    header: block.header,
                }
            }
        }

        pub struct FinalizeBlock {

        }
    }

    pub mod response {
        use tower_abci::response;

        #[derive(Default)]
        pub struct PrepareProposal;

        impl From<PrepareProposal> for response::BeginBlock {
            fn from(_: PrepareProposal) -> Self {
                Default::default()
            }
        }

        #[derive(Default)]
        pub struct VerifyHeader;

        #[derive(Default)]
        pub struct ProcessProposal;

        #[derive(Default)]
        pub struct RevertProposal;

        #[derive(Default)]
        pub struct FinalizeBlock {

        }

    }
}