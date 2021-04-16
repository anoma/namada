# Glossary

[comment]: <> (Each item in the list below has to be followed by 2 spaces with the description on the very next line)

- **orderbook**  
The orderbook must maintain a mempool of intents and gossips them to other
orderbooks via a p2p layer. Each orderbook maintains a list of interests that
describe what intents it is interested in.
- **intent**  
An expression of intent describes a particular trade an account agrees to.
- ***matchmaker**  
The matchmaker checks the orderbook mempool and tries to match expression of
intents together. For each match it crafts a valid transaction and submits it to
the base ledger.
- **validity predicate (VP)**  
A [validity predicate](/explore/design/ledger/vp.html) is a piece of code attached to an account that can accept or reject any state changes performed by a transaction in its sub-space.
