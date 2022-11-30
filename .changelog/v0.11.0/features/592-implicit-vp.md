- Added a validity predicate for implicit accounts. This is set in
  protocol parameters and may be changed via governance. Additionally,
  added automatic public key reveal in the client that use an implicit
  account that hasn't revealed its PK yet as a source. It's also
  possible to manually submit reveal transaction with  client command
  ([#592](https://github.com/anoma/namada/pull/592))