use std::convert::TryFrom;

use namada::ledger::events::Event;
use namada::proto::Tx;
use namada::types::address::Address;
use serde::Serialize;

use crate::cli::safe_exit;

