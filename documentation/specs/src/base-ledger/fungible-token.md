# Fungible token

The fungible token validity predicate authorises token balance changes on the basis of conservation-of-supply and approval-by-sender.

## Multitoken
A token balance is stored with a storage key. The token balance key should be `{token_addr}/balance/{owner_addr}` or `{token_addr}/{sub_prefix}/balance/{owner_addr}`. `{sub_prefix}` can have multiple key segments. These keys can be made with [token functions](https://github.com/anoma/namada/blob/5da82f093f10c0381865accba99f60c557360c51/core/src/types/token.rs).

We can have multitoken balances with the same token and the same owner by `{sub_prefix}`, e.g. a token balance received over IBC is managed in `{token_addr}/ibc/{ibc_token_hash}/balance/{receiver_addr}`. It is distinguished from the receiver's original balance in `{token_addr}/balance/{receiver_addr}` to know which chain the token was transferred from.

The transfers between the following keys are allowed:

| Source | Target |
|----|----|
| `{token_addr}/balance/{sender_addr}` | `{token_addr}/balance/{receiver_addr}` |
| `{token_addr}/{sub_prefix}/balance/{sender_addr}` | `{token_addr}/{sub_prefix}/balance/{receiver_addr}` |

A transfer can be allowed from a balance without `{sub_prefix}` to another one without `{sub_prefix}` and between balances with the same `{sub_prefix}`. The `{sub_prefix}` can be given with `--sub-prefix` argument when Namada CLI `namadac transfer`.

Some special transactions can transfer to another balance with the different `{sub_prefix}`. IBC transaction transfers from a balance with `{sub_prefix}` to another balance with a different `{sub_prefix}`. IBC transfers handle the sub prefix `ibc/{port_id}/{channel_id}` for the IBC escrow, mint, and burn accounts and the sub prefix `ibc/{ibc_token_hash}` for receiving a token. IBC transaction transfers a token between the following keys:

| IBC operation | Source | Target |
|----|----|----|
| Send (as the source) | `{token_addr}/balance/{sender_addr}` | `{token_addr}/ibc/{port_id}/{channel_id}/balance/IBC_ESCROW` |
| Send (to the source) | `{token_addr}/balance/{sender_addr}` | `{token_addr}/ibc/{port_id}/{channel_id}/balance/IBC_BURN` |
| Refund (when sending as the source) | `{token_addr}/ibc/{port_id}/{channel_id}/balance/IBC_ESCROW` | `{token_addr}/balance/{sender_addr}` |
| Refund (when sending to the source) | `{token_addr}/ibc/{port_id}/{channel_id}/balance/IBC_BURN` | `{token_addr}/balance/{sender_addr}` |
| Receive (as the source) | `{token_addr}/ibc/{port_id}/{channel_id}/balance/IBC_ESCROW` | `{token_addr}/balance/{receiver_addr}` |
| Receive (from the source) | `{token_addr}/ibc/{port_id}/{channel_id}/balance/IBC_MINT` | `{token_addr}/ibc/{ibc_token_hash}/balance/{receiver_addr}` |

[IBC token validity predicate](https://github.com/anoma/namada/blob/5da82f093f10c0381865accba99f60c557360c51/shared/src/ledger/ibc/vp/token.rs) should validate these transfers. These special transfers like IBC should be validated by not only the fungible token validity predicate but also other validity predicates.
