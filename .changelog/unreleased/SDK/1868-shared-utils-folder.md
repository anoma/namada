- The shared-utils topic ([#1868](https://github.com/anoma/namada/pull/1868)) moves the following:
  + _Modules_
    | From                                    | To                                   |
    |-----------------------------------------|--------------------------------------|
    | namada::ledger::tx                      | namada::sdk::tx                      |
    | namada::ledger::rpc                     | namada::sdk::rpc                     |
    | namada::ledger::signing                 | namada::sdk::signing                 |
    | namada::ledger::masp                    | namada::sdk::masp                    |
    | namada::ledger::args                    | namada::sdk::args                    |
    | namada::ledger::wallet::alias           | namada::sdk::wallet::alias           |
    | namada::ledger::wallet::derivation_path | namada::sdk::wallet::derivation_path |
    | namada::ledger::wallet::keys            | namada::sdk::wallet::keys            |
    | namada::ledger::wallet::pre_genesis     | namada::sdk::wallet::pre_genesis     |
    | namada::ledger::wallet::store           | namada::sdk::wallet::store           |
    | namada::types::error                    | namada::sdk::error                   |

  + _Types_

    | From                            | To                           |
    |---------------------------------|------------------------------|
    | namada::ledger::queires::Client | namada::sdk::queires::Client |
