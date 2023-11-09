use crate::facade::tendermint::v0_37::abci::{Request, Response};

pub mod shim {
    use std::convert::TryFrom;

    use thiserror::Error;

    use super::{Request as Req, Response as Resp};
    use crate::facade::tendermint_proto::v0_37::abci::{
        RequestApplySnapshotChunk, RequestCheckTx, RequestEcho, RequestInfo,
        RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot,
        RequestPrepareProposal, RequestProcessProposal, RequestQuery,
        ResponseApplySnapshotChunk, ResponseCheckTx, ResponseCommit,
        ResponseEcho, ResponseEndBlock, ResponseInfo, ResponseInitChain,
        ResponseListSnapshots, ResponseLoadSnapshotChunk,
        ResponseOfferSnapshot, ResponsePrepareProposal, ResponseQuery,
        VoteInfo,
    };
    use crate::node::ledger::shell;

    pub type TxBytes = prost::bytes::Bytes;

    #[derive(Error, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum Error {
        #[error("Error converting Request from ABCI to ABCI++: {0:?}")]
        ConvertReq(Req),
        #[error("Error converting Response from ABCI++ to ABCI: {0:?}")]
        ConvertResp(Response),
        #[error("{0:?}")]
        Shell(shell::Error),
    }

    /// Errors from the shell need to be propagated upward
    impl From<shell::Error> for Error {
        fn from(err: shell::Error) -> Self {
            Self::Shell(err)
        }
    }

    #[allow(clippy::large_enum_variant)]
    /// Our custom request types. It is the duty of the shim to change
    /// the request types coming from tower-abci to these before forwarding
    /// it to the shell
    ///
    /// Each request contains a custom payload type as well, which may
    /// be simply a unit struct
    pub enum Request {
        InitChain(RequestInitChain),
        Info(RequestInfo),
        Query(RequestQuery),
        PrepareProposal(RequestPrepareProposal),
        #[allow(dead_code)]
        VerifyHeader(request::VerifyHeader),
        ProcessProposal(RequestProcessProposal),
        #[allow(dead_code)]
        RevertProposal(request::RevertProposal),
        FinalizeBlock(request::FinalizeBlock),
        Commit,
        Flush,
        Echo(RequestEcho),
        CheckTx(RequestCheckTx),
        ListSnapshots,
        OfferSnapshot(RequestOfferSnapshot),
        LoadSnapshotChunk(RequestLoadSnapshotChunk),
        ApplySnapshotChunk(RequestApplySnapshotChunk),
    }

    /// Attempt to convert a tower-abci request to an internal one
    impl TryFrom<Req> for Request {
        type Error = Error;

        fn try_from(req: Req) -> Result<Request, Error> {
            match req {
                Req::InitChain(inner) => Ok(Request::InitChain(inner.into())),
                Req::Info(inner) => Ok(Request::Info(inner.into())),
                Req::Query(inner) => Ok(Request::Query(inner.into())),
                Req::Commit => Ok(Request::Commit),
                Req::Flush => Ok(Request::Flush),
                Req::Echo(inner) => Ok(Request::Echo(inner.into())),
                Req::CheckTx(inner) => Ok(Request::CheckTx(inner.into())),
                Req::ListSnapshots => Ok(Request::ListSnapshots),
                Req::OfferSnapshot(inner) => {
                    Ok(Request::OfferSnapshot(inner.into()))
                }
                Req::LoadSnapshotChunk(inner) => {
                    Ok(Request::LoadSnapshotChunk(inner.into()))
                }
                Req::ApplySnapshotChunk(inner) => {
                    Ok(Request::ApplySnapshotChunk(inner.into()))
                }
                Req::PrepareProposal(inner) => {
                    Ok(Request::PrepareProposal(inner.into()))
                }
                _ => Err(Error::ConvertReq(req)),
            }
        }
    }

    /// Custom response types. These will be returned by the shell along with
    /// custom payload types (which may be unit structs). It is the duty of
    /// the shim to convert these to responses understandable to tower-abci
    #[derive(Debug)]
    pub enum Response {
        InitChain(ResponseInitChain),
        Info(ResponseInfo),
        Query(ResponseQuery),
        PrepareProposal(response::PrepareProposal),
        VerifyHeader(response::VerifyHeader),
        ProcessProposal(response::ProcessProposal),
        RevertProposal(response::RevertProposal),
        FinalizeBlock(response::FinalizeBlock),
        EndBlock(ResponseEndBlock),
        Commit(ResponseCommit),
        Flush,
        Echo(ResponseEcho),
        CheckTx(ResponseCheckTx),
        ListSnapshots(ResponseListSnapshots),
        OfferSnapshot(ResponseOfferSnapshot),
        LoadSnapshotChunk(ResponseLoadSnapshotChunk),
        ApplySnapshotChunk(ResponseApplySnapshotChunk),
    }

    /// Attempt to convert response from shell to a tower-abci response type
    impl TryFrom<Response> for Resp {
        type Error = Error;

        fn try_from(resp: Response) -> Result<Resp, Error> {
            match resp {
                Response::InitChain(inner) => {
                    Ok(Resp::InitChain(inner.try_into().unwrap()))
                }
                Response::Info(inner) => {
                    Ok(Resp::Info(inner.try_into().unwrap()))
                }
                Response::Query(inner) => {
                    Ok(Resp::Query(inner.try_into().unwrap()))
                }
                Response::Commit(inner) => {
                    Ok(Resp::Commit(inner.try_into().unwrap()))
                }
                Response::Flush => Ok(Resp::Flush),
                Response::Echo(inner) => {
                    Ok(Resp::Echo(inner.try_into().unwrap()))
                }
                Response::CheckTx(inner) => {
                    Ok(Resp::CheckTx(inner.try_into().unwrap()))
                }
                Response::ListSnapshots(inner) => {
                    Ok(Resp::ListSnapshots(inner.try_into().unwrap()))
                }
                Response::OfferSnapshot(inner) => {
                    Ok(Resp::OfferSnapshot(inner.try_into().unwrap()))
                }
                Response::LoadSnapshotChunk(inner) => {
                    Ok(Resp::LoadSnapshotChunk(inner.try_into().unwrap()))
                }
                Response::ApplySnapshotChunk(inner) => {
                    Ok(Resp::ApplySnapshotChunk(inner.try_into().unwrap()))
                }
                Response::PrepareProposal(inner) => Ok(Resp::PrepareProposal(
                    ResponsePrepareProposal::from(inner).try_into().unwrap(),
                )),
                _ => Err(Error::ConvertResp(resp)),
            }
        }
    }

    /// Custom types for request payloads
    pub mod request {
        use std::convert::TryFrom;

        use namada::tendermint_proto::v0_37::abci::RequestBeginBlock;
        use namada::types::hash::Hash;
        use namada::types::storage::{BlockHash, Header};
        use namada::types::time::DateTimeUtc;

        use super::VoteInfo;
        use crate::facade::tendermint_proto::v0_37::abci::Misbehavior as Evidence;

        pub struct VerifyHeader;

        pub struct RevertProposal;

        /// A Tx and the result of calling Process Proposal on it
        #[derive(Debug, Clone)]
        pub struct ProcessedTx {
            pub tx: super::TxBytes,
            pub result: super::response::TxResult,
        }

        #[derive(Debug, Clone)]
        pub struct FinalizeBlock {
            pub hash: BlockHash,
            pub header: Header,
            pub byzantine_validators: Vec<Evidence>,
            pub txs: Vec<ProcessedTx>,
            pub proposer_address: Vec<u8>,
            pub votes: Vec<VoteInfo>,
        }

        impl From<RequestBeginBlock> for FinalizeBlock {
            fn from(req: RequestBeginBlock) -> FinalizeBlock {
                let header = req.header.unwrap();
                FinalizeBlock {
                    hash: BlockHash::default(),
                    header: Header {
                        hash: Hash::try_from(header.app_hash.as_slice())
                            .unwrap_or_default(),
                        time: DateTimeUtc::try_from(header.time.unwrap())
                            .unwrap(),
                        next_validators_hash: Hash::try_from(
                            header.next_validators_hash.as_slice(),
                        )
                        .unwrap(),
                    },
                    byzantine_validators: req.byzantine_validators,
                    txs: vec![],
                    proposer_address: header.proposer_address,
                    votes: req.last_commit_info.unwrap().votes,
                }
            }
        }
    }

    /// Custom types for response payloads
    pub mod response {
        use namada::ledger::events::Event;

        use crate::facade::tendermint_proto::v0_37::abci::{
            Event as TmEvent, ResponsePrepareProposal, ResponseProcessProposal,
            ValidatorUpdate,
        };
        use crate::facade::tendermint_proto::v0_37::types::ConsensusParams;

        #[derive(Debug, Default)]
        pub struct PrepareProposal {
            pub txs: Vec<super::TxBytes>,
        }

        impl From<PrepareProposal> for ResponsePrepareProposal {
            fn from(resp: PrepareProposal) -> Self {
                Self { txs: resp.txs }
            }
        }
        #[derive(Debug, Default)]
        pub struct VerifyHeader;

        #[derive(Debug, Default, Clone, PartialEq, Eq)]
        pub struct TxResult {
            pub code: u32,
            pub info: String,
        }

        #[derive(Debug, Default)]
        pub struct ProcessProposal {
            pub status: i32,
            pub tx_results: Vec<TxResult>,
        }

        impl From<&ProcessProposal> for ResponseProcessProposal {
            fn from(resp: &ProcessProposal) -> Self {
                Self {
                    status: resp.status,
                }
            }
        }

        #[derive(Debug, Default)]
        pub struct RevertProposal;

        #[derive(Debug, Default)]
        pub struct FinalizeBlock {
            pub events: Vec<Event>,
            pub validator_updates: Vec<ValidatorUpdate>,
            pub consensus_param_updates: Option<ConsensusParams>,
        }

        impl From<FinalizeBlock>
            for crate::facade::tendermint_proto::v0_37::abci::ResponseEndBlock
        {
            fn from(resp: FinalizeBlock) -> Self {
                Self {
                    events: resp
                        .events
                        .into_iter()
                        .map(TmEvent::from)
                        .collect(),
                    validator_updates: resp.validator_updates,
                    consensus_param_updates: resp.consensus_param_updates,
                }
            }
        }
    }
}
