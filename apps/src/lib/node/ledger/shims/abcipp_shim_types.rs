#[cfg(not(feature = "abcipp"))]
use tower_abci::{Request, Response};
#[cfg(feature = "abcipp")]
use tower_abci_abcipp::{Request, Response};

pub mod shim {
    use std::convert::TryFrom;

    #[cfg(not(feature = "abcipp"))]
    use tendermint_proto::abci::{
        RequestApplySnapshotChunk, RequestCheckTx, RequestCommit, RequestEcho,
        RequestFlush, RequestInfo, RequestInitChain, RequestListSnapshots,
        RequestLoadSnapshotChunk, RequestOfferSnapshot, RequestPrepareProposal,
        RequestProcessProposal, RequestQuery, ResponseApplySnapshotChunk,
        ResponseCheckTx, ResponseCommit, ResponseEcho, ResponseEndBlock,
        ResponseFlush, ResponseInfo, ResponseInitChain, ResponseListSnapshots,
        ResponseLoadSnapshotChunk, ResponseOfferSnapshot,
        ResponsePrepareProposal, ResponseQuery, VoteInfo as TendermintVoteInfo,
    };
    #[cfg(feature = "abcipp")]
    use tendermint_proto_abcipp::abci::{
        RequestApplySnapshotChunk, RequestCheckTx, RequestCommit, RequestEcho,
        RequestExtendVote, RequestFlush, RequestInfo, RequestInitChain,
        RequestListSnapshots, RequestLoadSnapshotChunk, RequestOfferSnapshot,
        RequestPrepareProposal, RequestProcessProposal, RequestQuery,
        RequestVerifyVoteExtension, ResponseApplySnapshotChunk,
        ResponseCheckTx, ResponseCommit, ResponseEcho, ResponseExtendVote,
        ResponseFlush, ResponseInfo, ResponseInitChain, ResponseListSnapshots,
        ResponseLoadSnapshotChunk, ResponseOfferSnapshot,
        ResponsePrepareProposal, ResponseQuery, ResponseVerifyVoteExtension,
        VoteInfo as TendermintVoteInfo,
    };
    use thiserror::Error;

    use super::{Request as Req, Response as Resp};
    use crate::node::ledger::shell;

    pub type TxBytes = Vec<u8>;

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
        #[cfg(feature = "abcipp")]
        ExtendVote(RequestExtendVote),
        #[cfg(feature = "abcipp")]
        VerifyVoteExtension(RequestVerifyVoteExtension),
        FinalizeBlock(request::FinalizeBlock),
        Commit(RequestCommit),
        Flush(RequestFlush),
        Echo(RequestEcho),
        CheckTx(RequestCheckTx),
        ListSnapshots(RequestListSnapshots),
        OfferSnapshot(RequestOfferSnapshot),
        LoadSnapshotChunk(RequestLoadSnapshotChunk),
        ApplySnapshotChunk(RequestApplySnapshotChunk),
    }

    /// Attempt to convert a tower-abci request to an internal one
    impl TryFrom<Req> for Request {
        type Error = Error;

        fn try_from(req: Req) -> Result<Request, Error> {
            match req {
                Req::InitChain(inner) => Ok(Request::InitChain(inner)),
                Req::Info(inner) => Ok(Request::Info(inner)),
                Req::Query(inner) => Ok(Request::Query(inner)),
                Req::Commit(inner) => Ok(Request::Commit(inner)),
                Req::Flush(inner) => Ok(Request::Flush(inner)),
                Req::Echo(inner) => Ok(Request::Echo(inner)),
                #[cfg(feature = "abcipp")]
                Req::ExtendVote(inner) => Ok(Request::ExtendVote(inner)),
                #[cfg(feature = "abcipp")]
                Req::VerifyVoteExtension(inner) => {
                    Ok(Request::VerifyVoteExtension(inner))
                }
                Req::CheckTx(inner) => Ok(Request::CheckTx(inner)),
                Req::ListSnapshots(inner) => Ok(Request::ListSnapshots(inner)),
                Req::OfferSnapshot(inner) => Ok(Request::OfferSnapshot(inner)),
                Req::LoadSnapshotChunk(inner) => {
                    Ok(Request::LoadSnapshotChunk(inner))
                }
                Req::ApplySnapshotChunk(inner) => {
                    Ok(Request::ApplySnapshotChunk(inner))
                }
                Req::PrepareProposal(inner) => {
                    Ok(Request::PrepareProposal(inner))
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
        PrepareProposal(ResponsePrepareProposal),
        VerifyHeader(response::VerifyHeader),
        ProcessProposal(response::ProcessProposal),
        RevertProposal(response::RevertProposal),
        #[cfg(feature = "abcipp")]
        ExtendVote(ResponseExtendVote),
        #[cfg(feature = "abcipp")]
        VerifyVoteExtension(ResponseVerifyVoteExtension),
        FinalizeBlock(response::FinalizeBlock),
        #[cfg(not(feature = "abcipp"))]
        EndBlock(ResponseEndBlock),
        Commit(ResponseCommit),
        Flush(ResponseFlush),
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
                Response::InitChain(inner) => Ok(Resp::InitChain(inner)),
                Response::Info(inner) => Ok(Resp::Info(inner)),
                Response::Query(inner) => Ok(Resp::Query(inner)),
                Response::Commit(inner) => Ok(Resp::Commit(inner)),
                Response::Flush(inner) => Ok(Resp::Flush(inner)),
                Response::Echo(inner) => Ok(Resp::Echo(inner)),
                Response::CheckTx(inner) => Ok(Resp::CheckTx(inner)),
                Response::ListSnapshots(inner) => {
                    Ok(Resp::ListSnapshots(inner))
                }
                Response::OfferSnapshot(inner) => {
                    Ok(Resp::OfferSnapshot(inner))
                }
                Response::LoadSnapshotChunk(inner) => {
                    Ok(Resp::LoadSnapshotChunk(inner))
                }
                Response::ApplySnapshotChunk(inner) => {
                    Ok(Resp::ApplySnapshotChunk(inner))
                }
                Response::PrepareProposal(inner) => {
                    Ok(Resp::PrepareProposal(inner))
                }
                #[cfg(feature = "abcipp")]
                Response::ExtendVote(inner) => Ok(Resp::ExtendVote(inner)),
                #[cfg(feature = "abcipp")]
                Response::VerifyVoteExtension(inner) => {
                    Ok(Resp::VerifyVoteExtension(inner))
                }
                _ => Err(Error::ConvertResp(resp)),
            }
        }
    }

    /// Custom types for request payloads
    pub mod request {
        use std::convert::TryFrom;

        use namada::ledger::pos::types::VoteInfo;
        #[cfg(not(feature = "abcipp"))]
        use namada::tendermint_proto::abci::RequestBeginBlock;
        use namada::types::hash::Hash;
        use namada::types::storage::{BlockHash, Header};
        use namada::types::time::DateTimeUtc;
        #[cfg(not(feature = "abcipp"))]
        use tendermint_proto::abci::Misbehavior as Evidence;
        #[cfg(feature = "abcipp")]
        use tendermint_proto_abcipp::abci::{
            Misbehavior as Evidence, RequestFinalizeBlock,
        };

        use super::TendermintVoteInfo;

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
            #[cfg(feature = "abcipp")]
            pub proposer_address: Vec<u8>,
            pub votes: Vec<VoteInfo>,
        }

        #[cfg(feature = "abcipp")]
        impl From<RequestFinalizeBlock> for FinalizeBlock {
            fn from(req: RequestFinalizeBlock) -> FinalizeBlock {
                FinalizeBlock {
                    hash: BlockHash::try_from(req.hash.as_slice()).unwrap(),
                    header: Header {
                        hash: Hash::try_from(req.hash.as_slice()).unwrap(),
                        time: DateTimeUtc::try_from(req.time.unwrap()).unwrap(),
                        next_validators_hash: Hash::try_from(
                            req.next_validators_hash.as_slice(),
                        )
                        .unwrap(),
                    },
                    byzantine_validators: req.byzantine_validators,
                    txs: vec![],
                    #[cfg(feature = "abcipp")]
                    proposer_address: req.proposer_address,
                    votes: req
                        .decided_last_commit
                        .unwrap()
                        .votes
                        .iter()
                        .map(|tm_vote_info| {
                            vote_info_to_tendermint(tm_vote_info.clone())
                        })
                        .collect(),
                }
            }
        }

        fn vote_info_to_tendermint(info: TendermintVoteInfo) -> VoteInfo {
            let val_info = info.validator.clone().unwrap();
            VoteInfo {
                validator_address: info.validator.unwrap().address,
                validator_vp: val_info.power as u64,
                signed_last_block: info.signed_last_block,
            }
        }

        #[cfg(not(feature = "abcipp"))]
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
                    votes: req
                        .last_commit_info
                        .unwrap()
                        .votes
                        .iter()
                        .map(|tm_vote_info| {
                            vote_info_to_tendermint(tm_vote_info.clone())
                        })
                        .collect(),
                }
            }
        }
    }

    /// Custom types for response payloads
    pub mod response {
        use namada::ledger::events::Event;
        #[cfg(feature = "abcipp")]
        use namada::ledger::events::EventLevel;

        use crate::facade::tendermint_proto::abci::{
            Event as TmEvent, ResponseProcessProposal, ValidatorUpdate,
        };
        #[cfg(not(feature = "abcipp"))]
        use crate::facade::tendermint_proto::types::ConsensusParams;
        #[cfg(feature = "abcipp")]
        use crate::facade::tendermint_proto::{
            abci::{ExecTxResult, ResponseFinalizeBlock},
            types::ConsensusParams,
        };

        #[derive(Debug, Default)]
        pub struct VerifyHeader;

        #[derive(Debug, Default, Clone)]
        pub struct TxResult {
            pub code: u32,
            pub info: String,
        }

        #[cfg(feature = "abcipp")]
        impl From<TxResult> for ExecTxResult {
            fn from(TxResult { code, info }: TxResult) -> Self {
                ExecTxResult {
                    code,
                    info,
                    ..Default::default()
                }
            }
        }

        #[cfg(feature = "abcipp")]
        impl From<&ExecTxResult> for TxResult {
            fn from(ExecTxResult { code, info, .. }: &ExecTxResult) -> Self {
                TxResult {
                    code: *code,
                    info: info.clone(),
                }
            }
        }

        #[derive(Debug, Default)]
        pub struct ProcessProposal {
            pub status: i32,
            pub tx_results: Vec<TxResult>,
        }

        #[cfg(feature = "abcipp")]
        impl From<&ProcessProposal> for ResponseProcessProposal {
            fn from(resp: &ProcessProposal) -> Self {
                Self {
                    status: resp.status,
                    tx_results: resp
                        .tx_results
                        .iter()
                        .map(|res| ExecTxResult::from(res.clone()))
                        .collect(),
                    ..Default::default()
                }
            }
        }

        #[cfg(not(feature = "abcipp"))]
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

        #[cfg(feature = "abcipp")]
        impl From<FinalizeBlock> for ResponseFinalizeBlock {
            fn from(resp: FinalizeBlock) -> Self {
                ResponseFinalizeBlock {
                    tx_results: resp
                        .events
                        .iter()
                        .filter(|event| matches!(event.level, EventLevel::Tx))
                        .map(|event| ExecTxResult {
                            code: event
                                .get("code")
                                .map(|code| code.parse::<u32>().unwrap())
                                .unwrap_or_default(),
                            log: event
                                .get("log")
                                .map(|log| log.to_owned())
                                .unwrap_or_default(),
                            info: event
                                .get("info")
                                .map(|info| info.to_owned())
                                .unwrap_or_default(),
                            gas_used: event
                                .get("gas_used")
                                .map(|gas| gas.parse::<i64>().unwrap())
                                .unwrap_or_default(),
                            ..Default::default()
                        })
                        .collect(),
                    events: resp
                        .events
                        .into_iter()
                        .map(TmEvent::from)
                        .collect(),
                    consensus_param_updates: resp.consensus_param_updates,
                    validator_updates: resp.validator_updates,
                    ..Default::default()
                }
            }
        }

        #[cfg(not(feature = "abcipp"))]
        impl From<FinalizeBlock> for tendermint_proto::abci::ResponseEndBlock {
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
