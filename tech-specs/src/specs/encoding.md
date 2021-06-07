# Encoding

All the data fields are REQUIRED, unless specified otherwise.

## The ledger

### Transactions

Transactions MUST be encoded using [proto3](https://developers.google.com/protocol-buffers/docs/reference/proto3-spec) in the format as defined for [message Tx](https://github.com/anomanetwork/anoma/blob/master/proto/types.proto).

| Name      | Type                      | Description                                    | Field Number |
|-----------|---------------------------|------------------------------------------------|--------------|
| code      | bytes                     | Transaction WASM code.                         |            1 |
| data      | optional bytes            | Transaction data (OPTIONAL).                   |            2 |
| timestamp | google.protobuf.Timestamp | Timestamp of when the transaction was created. |            3 |
