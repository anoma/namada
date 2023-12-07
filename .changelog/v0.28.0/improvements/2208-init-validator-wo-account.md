- A new `tx_become_validator` replaces `tx_init_validator`. This tx doesn't
  initialize a new account and instead it modifies an existing established
  address to become a validator. This currently requires that there are no
  delegations on the source account before it can become a validator (if there
  are some, they have to be unbonded, but they don't have to be withdrawn).
  A new client command `become-validator` is added that requires an `--address`.
  The client command `init-validator` is kept for convenience and updated to
  send `tx_init_account` tx before `tx_become_validator`.
  ([\#2208](https://github.com/anoma/namada/pull/2208))