- Speeds up client commands on networks with massive balances.toml
  files. Previously, to retrieve the native token of some network,
  we had to parse these giant files. Now, we only parse the
  necessary genesis toml files required to retrieve the native token.
  ([\#3655](https://github.com/anoma/namada/pull/3655))