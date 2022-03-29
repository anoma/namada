# Testnets

This section describes how to connect to the various testnets and to test selected features.

* Transparent to shielded payment: `anomac transfer --source Bertha --amount 50 --token BTC --payment-address 9cb63488b1d6ef25f069b6eb5bba2eee3dcf22bc10b2063a1fbcb91964341d75837bdce3e2fe3ec9c1e005`
* Shielded to transparent payment: `anomac transfer --target Bertha --amount 45 --token BTC --spending-key AA`
* View shielded balance using spending key: `anomac balance --spending-key AA`
* View shielded balance using viewing key: `anomac balance --viewing-key 628a9956322f3f7d20b19801d9b4a8f3cb4b8b756a26ef2477feb5264be7b808c920996f37a79433d08e27fefcda0b6736c296b1073734a4ee35d11368f2b52ef14d7c1749cc8119ecc8a894f696992453f2dd78ef1e9d74172b2a5ef7cc8c50`
* Derive view key from spending key: `anomaw masp derive-view-key --spending-key AA`
* Generate payment address from spending key: `anomaw masp gen-payment-addr --spending-key AA`
* Generate payment address from viewing key: `anomaw masp gen-payment-addr --viewing-key 628a9956322f3f7d20b19801d9b4a8f3cb4b8b756a26ef2477feb5264be7b808c920996f37a79433d08e27fefcda0b6736c296b1073734a4ee35d11368f2b52ef14d7c1749cc8119ecc8a894f696992453f2dd78ef1e9d74172b2a5ef7cc8c50`
* Shielded to shielded payment: `anomac transfer --spending-key AA --amount 5 --token BTC --payment-address 9cb63488b1d6ef25f069b6eb5bba2eee3dcf22bc10b2063a1fbcb91964341d75837bdce3e2fe3ec9c1e005 --signer Albert`
