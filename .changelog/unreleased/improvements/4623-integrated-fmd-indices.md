- Closes [#4621](https://github.com/anoma/namada/issues/4621)

- For the MASP Indexer client, now only fetches of MASP txs included in an index set computed via FMD if such a set is present. Also uses the set to reduce the number of trial decryptions. This PR does not handle loading in FMD index sets. That will be determined later.
([\#4623](https://github.com/anoma/namada/pull/4623))