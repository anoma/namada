use namada_core::ledger::governance::storage::proposal::StorageProposal;
use namada_core::ledger::governance::utils::Vote;

use crate::ledger::queries::types::RequestCtx;
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::ledger::storage_api;
/// `Gov`path router type
pub struct Gov {
    prefix: String,
}
impl Gov {
    /// Construct this router as a root router
    pub const fn new() -> Self {
        Self {
            prefix: String::new(),
        }
    }

    #[allow(dead_code)]
    /// Construct this router as a sub-router at the given prefix path
    pub const fn sub(prefix: String) -> Self {
        Self { prefix }
    }

    #[allow(dead_code)]
    /// Get a path to query `proposal_id_votes`.
    pub fn proposal_id_votes_path(&self, id: &u64) -> String {
        itertools::join(
            [
                Some(std::borrow::Cow::from(&self.prefix)),
                std::option::Option::Some(std::borrow::Cow::from("proposal")),
                std::option::Option::Some(std::borrow::Cow::from(
                    id.to_string(),
                )),
                std::option::Option::Some(std::borrow::Cow::from("vote")),
            ]
            .into_iter()
            .filter_map(|x| x),
            "/",
        )
    }

    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "async-client"))]
    /// Request a simple borsh-encoded value from `proposal_id_votes`, without
    /// any additional request data, specified block height or proof.
    pub async fn proposal_id_votes<CLIENT>(
        &self,
        client: &CLIENT,
        id: &u64,
    ) -> std::result::Result<
        Vec<Vote>,
        <CLIENT as crate::ledger::queries::Client>::Error,
    >
    where
        CLIENT: crate::ledger::queries::Client + std::marker::Sync,
    {
        let path = self.proposal_id_votes_path(id);
        let data = client.simple_request(path).await?;
        let decoded: Vec<Vote> =
            borsh::BorshDeserialize::try_from_slice(&data[..])?;
        Ok(decoded)
    }

    #[allow(dead_code)]
    /// Get a path to query `proposal_id`.
    pub fn proposal_id_path(&self, id: &u64) -> String {
        itertools::join(
            [
                Some(std::borrow::Cow::from(&self.prefix)),
                std::option::Option::Some(std::borrow::Cow::from("proposal")),
                std::option::Option::Some(std::borrow::Cow::from(
                    id.to_string(),
                )),
            ]
            .into_iter()
            .filter_map(|x| x),
            "/",
        )
    }

    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "async-client"))]
    /// Request a simple borsh-encoded value from `proposal_id`, without any
    /// additional request data, specified block height or proof.
    pub async fn proposal_id<CLIENT>(
        &self,
        client: &CLIENT,
        id: &u64,
    ) -> std::result::Result<
        Option<StorageProposal>,
        <CLIENT as crate::ledger::queries::Client>::Error,
    >
    where
        CLIENT: crate::ledger::queries::Client + std::marker::Sync,
    {
        let path = self.proposal_id_path(id);
        let data = client.simple_request(path).await?;
        dbg!(&data);
        let decoded: Option<StorageProposal> =
            borsh::BorshDeserialize::try_from_slice(&data[..])?;
        Ok(decoded)
    }
}
impl crate::ledger::queries::Router for Gov {
    #[allow(unused_assignments)]
    fn internal_handle<D, H>(
        &self,
        ctx: crate::ledger::queries::RequestCtx<'_, D, H>,
        request: &crate::ledger::queries::RequestQuery,
        start: usize,
    ) -> crate::ledger::storage_api::Result<
        crate::ledger::queries::EncodedResponseQuery,
    >
    where
        D: 'static
            + crate::ledger::storage::DB
            + for<'iter> crate::ledger::storage::DBIter<'iter>
            + Sync,
        H: 'static + crate::ledger::storage::StorageHasher + Sync,
    {
        use crate::ledger::queries::router::find_next_slash_index;
        use crate::ledger::storage_api::ResultExt;
        loop {
            let mut start = start;
            if request.path.is_empty() || &request.path[..1] != "/" {
                break;
            }
            start += 1;
            if start >= request.path.len() {
                break;
            }
            let mut end = find_next_slash_index(&request.path, start);
            if &request.path[start..end] == "proposal" {
                start = end;
            } else {
                break;
            }
            if start + 1 < request.path.len() {
                start += 1;
            }
            end = find_next_slash_index(&request.path, start);
            let id: u64;
            end = request.path.len();
            match request.path[start..end].parse::<u64>() {
                Ok(parsed) => id = parsed,
                Err(_) => break,
            }
            if !(end == request.path.len()
                || end == request.path.len() - 1 && &request.path[end..] == "/")
            {
                break;
            }
            crate::ledger::queries::require_latest_height(&ctx, request)?;
            crate::ledger::queries::require_no_proof(request)?;
            crate::ledger::queries::require_no_data(request)?;
            let data = proposal_id(ctx, id)?;
            dbg!(&data);
            let data = borsh::BorshSerialize::try_to_vec(&data)
                .into_storage_result()?;
            dbg!(&data);
            return Ok(crate::ledger::queries::EncodedResponseQuery {
                data,
                info: Default::default(),
                proof: None,
            });
        }
        loop {
            let mut start = start;
            if request.path.is_empty() || &request.path[..1] != "/" {
                break;
            }
            start += 1;
            if start >= request.path.len() {
                break;
            }
            let mut end = find_next_slash_index(&request.path, start);
            if &request.path[start..end] == "proposal" {
                start = end;
            } else {
                break;
            }
            if start + 1 < request.path.len() {
                start += 1;
            }
            end = find_next_slash_index(&request.path, start);
            let id: u64;
            match request.path[start..end].parse::<u64>() {
                Ok(parsed) => id = parsed,
                Err(_) => break,
            }
            start = end;
            if start + 1 < request.path.len() {
                start += 1;
            }
            end = find_next_slash_index(&request.path, start);
            if &request.path[start..end] == "vote" {
                start = end;
            } else {
                break;
            }
            if start + 1 < request.path.len() {
                start += 1;
            }
            end = find_next_slash_index(&request.path, start);
            if !(end == request.path.len()
                || end == request.path.len() - 1 && &request.path[end..] == "/")
            {
                break;
            }
            crate::ledger::queries::require_latest_height(&ctx, request)?;
            crate::ledger::queries::require_no_proof(request)?;
            crate::ledger::queries::require_no_data(request)?;
            let data = proposal_id_votes(ctx, id)?;
            let data = borsh::BorshSerialize::try_to_vec(&data)
                .into_storage_result()?;
            return Ok(crate::ledger::queries::EncodedResponseQuery {
                data,
                info: Default::default(),
                proof: None,
            });
        }
        return Err(crate::ledger::queries::router::Error::WrongPath(
            request.path.clone(),
        ))
        .into_storage_result();
    }
}
/// `GOV` path router
pub const GOV: Gov = Gov::new();
/// Find if the given address belongs to a validator account.
fn proposal_id<D, H>(
    ctx: RequestCtx<'_, D, H>,
    id: u64,
) -> storage_api::Result<Option<StorageProposal>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::governance::get_proposal_by_id(ctx.wl_storage, id)
}
/// Find if the given address belongs to a validator account.
fn proposal_id_votes<D, H>(
    ctx: RequestCtx<'_, D, H>,
    id: u64,
) -> storage_api::Result<Vec<Vote>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::governance::get_proposal_votes(ctx.wl_storage, id)
}
