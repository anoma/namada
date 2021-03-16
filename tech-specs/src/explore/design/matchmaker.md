# matchmaker

The matchmaker has the task to craft transaction based on intent and inject them
into the ledger.

A wasm program wasm must be attached to any matchmaker with some specific
entrypoint (TDB). This program is feed with intents data and craft transaction.
The matchmaker should include a payement for himself in the transaction to
reembourse himself of the fee he had to pay.

idea/question:
  * I'm not yet clear on how the transaction must be crafted, a tx template
    where the program generate a new file based on the template seems like a
    easy first design but might not be expressive enough for what we want.
  * mutiple wasm program runs in parralel where each try to match intent of
    different "types" (i.e. asset exchange, default rate, community
    defined exchange type, ...)

## process

![matchmaker process](./gossip/matchmaker.svg "matchmaker process")
