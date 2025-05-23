Partially closes [#4645](https://github.com/anoma/namada/issues/4645)

This PR allows the namada client to perform two key management actions:
- add to a config file
- use the config file to register fmd keys with Kassandra services
  
Furthermore, it adds hashes of FMD keys derived from viewing keys to the wallet file under the viewing key alias. This PR does not handle querying the services or updating the shielded context accordingly.
([\#4646](https://github.com/anoma/namada/pull/4646))