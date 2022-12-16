## File System Wallet

By default, the Namada Wallet is stored under `.namada/{chain_id}/wallet.toml` where keys are stored encrypted. You can change the default base directory path with `--base-dir` and you can allow the storage of unencrypted keypairs with the flag `--unsafe-dont-encrypt`.

If the wallet doesn't already exist, it will be created for you as soon as you run a command that tries to access the wallet. A newly created wallet will be pre-loaded with some internal addresses like `pos`, `pos_slash_pool`, `masp` and more.

Currently, the Namada client can load the password via:

- **Stdin:** the client will prompt for a password.
- **Env variable:** by exporting a ENV variable called `NAMADA_WALLET_PASSWORD` with value of the actual password.
- **File:** by exporting an ENV variable called `NAMADA_WALLET_PASSWORD_FILE` with value containing the path to a file containing the password.