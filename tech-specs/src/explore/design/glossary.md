# Glossary

[comment]: <> (Each item in the list below has to be followed by 2 spaces with the description on the very next line)

- orderbook  
The orderbook must maintains a mempool of intents and gossip them to other Orderbook. Each orderbook maintains a list of interest that describe what assets it's interested in.
- intent  
An expression of intents describe a particular trade an account agrees on.
- matchmaker  
The matchmaker checks the orderbook mempool and try to match expression of intents together. For each match it craft a valid transaction and add it to the ledger.
- validity predicate (VP)  
A [validity predicate](/explore/design/ledger/vp.html) is a piece of code attached to an account that can accept or reject any state changes performed by a transaction in it's sub-space.
