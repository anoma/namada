use namada_test_utils::tx_data::TxWriteData;
use namada_tx_prelude::*;

const TX_NAME: &str = "tx_write";

fn log(msg: &str) {
    log_string(format!("[{}] {}", TX_NAME, msg))
}

fn fatal(msg: &str, err: impl std::error::Error) -> ! {
    log(&format!("ERROR: {} - {:?}", msg, err));
    panic!()
}

fn fatal_msg(msg: &str) -> ! {
    log(msg);
    panic!()
}

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = match tx_data.to_ref().data() {
        Some(data) => {
            log(&format!("got data ({} bytes)", data.len()));
            data
        }
        None => {
            fatal_msg("no data provided");
        }
    };
    let TxWriteData { key, value } =
        match TxWriteData::try_from_slice(&data[..]) {
            Ok(write_op) => {
                log(&format!(
                    "parsed WriteOp to key {} ({} bytes)",
                    &write_op.key,
                    &write_op.value.len(),
                ));
                write_op
            }
            Err(error) => fatal("deserializing WriteOp", error),
        };
    let existing_value: Option<String> = ctx.read(&key)?;
    match existing_value {
        Some(existing_value) => {
            log(&format!("already present value is {}", existing_value));
        }
        None => {
            log("no already present value");
        }
    }
    log(&format!("attempting to write new value to key {}", key));
    // using `ctx.write_bytes` instead of `ctx.write` here, as we want to
    // write the actual bytes, not a Borsh-serialization of a `Vec<u8>`
    ctx.write_bytes(&key, &value[..])?;
    Ok(())
}
