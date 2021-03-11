# Accounts

tracking issue <https://github.com/heliaxdev/rd-pm/issues/25>

TODO Detail the account types, their data, addresses, etc.

## Dynamic storage sub-space

Each account can have associated dynamic account state in the storage. This state may be comprised of key/value pairs of the built-in supported types and values may also be arbitrary user bytes.

TODO how are these read and written by tx code and read by VPs? Because VPs are associated with specific account, there isn't much restriction needed on the data structure. For tx code, should there be some kind of derived schema or storage traits?
