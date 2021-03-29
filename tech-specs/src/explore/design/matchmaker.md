# matchmaker

The matchmaker has the task to craft transactions from intents and inject them
into the ledger.

A wasm program with implementation of intent-matching logic can be attached to a matchmaker with a specific
entrypoint (TBD). This program is fed the intents data and it should produce transactions.
The matchmaker should include in the transactions a small payment to reimburse itself for the fees it has to pay to inject the transactions into the ledger.

## process

![matchmaker process](./gossip/matchmaker.svg "matchmaker process")
