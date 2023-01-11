# Fungible token

The fungible token validity predicate authorises token balance changes on the basis of conservation-of-supply and approval-by-sender.

## Multitoken
A token balance is stored with a storage key. The token balance key should be `{token_addr}/balance/{owner_addr}` or `{token_addr}/{sub_prefix}/balance/{owner_addr}`. `{sub_prefix}` can have multiple key segments. These keys can be made with [token functions](https://github.com/anoma/namada/blob/5da82f093f10c0381865accba99f60c557360c51/core/src/types/token.rs).

We can have multitoken balances with the same token and the same owner by `{sub_prefix}`, e.g. a token balance received over IBC is managed in `{token_addr}/ibc/{ibc_token_hash}/balance/{receiver_addr}`. It is distinguished from the receiver's original balance in `{token_addr}/balance/{receiver_addr}` to know which chain the token was transferred from.

It is allowed to transfer an amount from a balance to another balance with the same `{sub_prefix}`. Though IBC transfer would transfer a balance to another balance with the different `{sub_prefix}`, [IBC token validity predicate](https://github.com/anoma/namada/blob/5da82f093f10c0381865accba99f60c557360c51/shared/src/ledger/ibc/vp/token.rs) should validate the transfer. These special transfers like IBC should be validated by not only the fungible token validity predicate but also other validity predicates.
