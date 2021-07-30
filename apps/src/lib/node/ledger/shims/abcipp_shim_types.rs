use tower_abci::{Request, Response};

pub mod shim {
    use std::convert::{TryFrom, TryInto};
    use tendermint_proto::abci::{
        RequestInitChain, RequestInfo, RequestQuery, RequestCommit,
        RequestFlush, RequestSetOption, RequestEcho, RequestCheckTx,
        RequestListSnapshots, RequestOfferSnapshot, RequestLoadSnapshotChunk,
        RequestApplySnapshotChunk, ResponseInitChain, ResponseInfo,
        ResponseQuery, ResponseCommit, ResponseFlush, ResponseSetOption,
        ResponseEcho, ResponseCheckTx, ResponseListSnapshots, ResponseOfferSnapshot,
        ResponseLoadSnapshotChunk, ResponseApplySnapshotChunk
    };
    use thiserror;

    use super::Request as Req;
    use super::Response as Resp;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Error converting Request from ABCI to ABCI++: {:0?}")]
        ConvertReq(Req),
        #[error("Error converting Response from ABCI++ to ABCI: {:0?}")]
        ConvertResp(Res),
    }

    pub enum Request {
        InitChain(RequestInitChain),
        Info(RequestInfo),
        Query(RequestQuery),
        PrepareProposal(request::PrepareProposal),
        VerifyHeader(request::VerifyHeader),
        ProcessProposal(request::ProcessProposal),
        RevertProposal(request::RevertProposal),
        ExtendVote(request::ExtendVote),
        VerifyVoteExtension(request::VerifyVoteExtension),
        FinalizeBlock(request::FinalizeBlock),
        Commit(RequestCommit),
        Flush(RequestFlush),
        SetOption(RequestSetOption),
        Echo(RequestEcho),
        CheckTx(RequestCheckTx),
        ListSnapshots(RequestListSnapshots),
        OfferSnapshot(RequestOfferSnapshot),
        LoadSnapshotChunk(RequestLoadSnapshotChunk),
        ApplySnapshotChunk(RequestApplySnapshotChunk),
    }

    impl TryFrom<Req> for Request {
        type Error = Error;

        fn try_from(req: Req) -> Result<Request, Error> {
            match req {
                Req::InitChain(inner) => Ok(Request::InitChain(inner)),
                Req::Info(inner) => Ok(Request::Info(inner)),
                Req::Query(inner) => Ok(Request::Query(inner)),
                // TODO: needed?
                Req::BeginBlock(inner) => Ok(Request::PrepareProposal(inner.into())),
                Req::EndBlock(inner) => Ok(Request::FinalizeBlock(inner.into())),
                Req::Commit(inner) => Ok(Request::Commit(inner)),
                Req::Flush(inner) => Ok(Request::Flush(inner)),
                Req::SetOption(inner) => Ok(Request::SetOption(inner)),
                Req::Echo(inner) => Ok(Reqest::Echo(inner)),
                Req::CheckTx(inner) => Ok(Request::CheckTx(inner)),
                Req::ListSnapshots(inner) => Ok(Request::ListSnapshots(inner)),
                Req::OfferSnapshot(inner) => Ok(Request::OfferSnapshot(inner)),
                Req::LoadSnapshotChunk(inner) => Ok(Request::LoadSnapshotChunk(inner)),
                Req::ApplySnapshotChunk(inner) => Ok(Request::ApplySnapshotChunk(inner)),
                _ => Err(Error::ConvertReq(req))
            }
        }
    }

    pub enum Response {
        InitChain(ResponseInitChain),
        Info(ResponseInfo),
        Query(ResponseQuery),
        PrepareProposal(response::PrepareProposal),
        VerifyHeader(response::VerifyHeader),
        ProcessProposal(response::ProcessProposal),
        RevertProposal(response::RevertProposal),
        ExtendVote(response::ExtendVote),
        VerifyVoteExtension(repsonse::VerifyVoteExtension),
        FinalizeBlock(response::FinalizeBlock),
        Commit(ResponseCommit),
        Flush(ResponseFlush),
        SetOption(ResponseSetOption),
        Echo(ResponseEcho),
        CheckTx(ResponseCheckTx),
        ListSnapshots(ResponseListSnapshots),
        OfferSnapshot(ResponseOfferSnapshot),
        LoadSnapshotChunk(ResponseLoadSnapshotChunk),
        ApplySnapshotChunk(ResponseApplySnapshotChunk),
    }

    impl TryFrom<Response> for Resp {
        type Error = Error;

        fn try_from(resp: Response) -> Result<Resp, Error> {
            match resp {
                Response::InitChain(inner) => Ok(Resp::InitChain(inner)),
                Response::Info(inner) => Ok(Resp::Info(inner)),
                Response::Query(inner) => Ok(Resp::Query(inner)),
                // TODO: needed?
                Response::PrepareProposal(inner) => Ok(Resp::BeginBlock(inner.into())),
                Response::FinalizeBlock(inner) => Ok(Resp::EndBlock(inner.into())),
                Response::Commit(inner) => Ok(Resp::Commit(inner)),
                Response::Flush(inner) => Ok(Resp::Flush(inner)),
                Response::SetOption(inner) => Ok(Resp::SetOption(inner)),
                Response::Echo(inner) => Ok(Resp::Echo(inner)),
                Response::CheckTx(inner) => Ok(Resp::CheckTx(inner)),
                Response::ListSnapshots(inner) => Ok(Resp::ListSnapshots(inner)),
                Response::OfferSnapshot(inner) => Ok(Resp::OfferSnapshot(inner)),
                Response::LoadSnapshotChunk(inner) => Ok(Resp::LoadSnapshotChunk(inner)),
                Response::ApplySnapshotChunk(inner) => Ok(Resp::ApplySnapshotChunk(inner)),
                _ => Err(Error::ConvertResp(resp))
            }
        }
    }

    pub mod request {
        use anoma_shared::types::storage::{BlockHash, BlockHeight};
        use tendermint_proto::types::Header;
        use tendermint_proto::abci::{RequestBeginBlock, RequestEndBlock};

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

        pub struct VerifyHeader;
        pub struct ProcessProposal;
        pub struct RevertProposal;
        pub struct ExtendVote;
        pub struct VerifyVoteExtension;

        pub struct FinalizeBlock {

        }

        impl From<RequestEndBlock> for FinalizeBlock {
            fn from(req: RequestEndBlock) -> Self {

            }
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
        pub struct ExtendVote;

        #[derive(Default)]
        pub struct VerifyVoteExtension;

        #[derive(Default)]
        pub struct FinalizeBlock {

        }

    }
}