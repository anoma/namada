use byteorder::{BigEndian, ByteOrder};

// Simple counter application. Its only state is a u64 count
// We use BigEndian to serialize the data across transactions calls
pub struct Shell {
    count: u64,
}

pub type Transaction<'a> = anoma::Transaction<'a>;

pub enum MempoolTxType {
    /// A transaction that has not been validated by this node before
    NewTransaction,
    /// A transaction that has been validated at some previous level that may
    /// need to be validated again
    RecheckTransaction,
}
pub type MempoolValidationResult<'a> = Result<(), &'a str>;
pub type ApplyResult<'a> = Result<(), &'a str>;

pub struct MerkleRoot(pub Vec<u8>);

impl Shell {
    pub fn new() -> Self {
        Self { count: 0 }
    }
}

// Convert incoming tx data to the proper BigEndian size. txs.len() > 8 will
// return 0
fn parse_tx<'a>(tx: Transaction) -> Result<u64, &'a str> {
    if tx.data.len() > 8 {
        return Err("Failed to parse the transaction");
    }
    let pad = 8 - tx.data.len();
    let mut x = vec![0; pad];
    x.extend(tx.data.iter());
    return Ok(BigEndian::read_u64(x.as_slice()));
}

impl Shell {
    /// Validate a transaction request. On success, the transaction will
    /// included in the mempool and propagated to peers, otherwise it will be
    /// rejected.
    pub fn mempool_validate(
        &mut self,
        tx: Transaction,
        _prevalidation_type: MempoolTxType,
    ) -> MempoolValidationResult {
        // Get the Tx [u8] and convert to u64
        let c = parse_tx(tx)?;

        // Validation logic.
        // Rule: Transactions must be incremental: 1,2,3,4...
        if c != self.count + 1 {
            return Err("Count must be incremental!");
        }
        // Update state to keep state correct for next check_tx call
        self.count = c;
        Ok(())
    }

    /// Validate and apply a transaction.
    pub fn apply_tx(&mut self, tx: Transaction) -> ApplyResult {
        // Get the Tx [u8]
        let c = parse_tx(tx)?;
        // Update state
        self.count = c;
        // Return default code 0 == bueno
        Ok(())
    }

    /// Persist the application state and return the Merkle root hash.
    pub fn commit(&mut self) -> MerkleRoot {
        // Convert count to bits
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf, self.count);
        // Set data so last state is included in the block
        MerkleRoot(buf.to_vec())
    }
}
