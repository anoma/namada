# Web Wallet

## Application Features

The application consist of the an UI that allows the user to perform the following actions in an easy to use and consistent web application:

### Seed Phrase

[hifi Designs](https://www.figma.com/file/aiWZpaXjPLW6fDjE7dpFaU/Projects-2021?node-id=4610%3A5890)

- Can setup a new seed phrase and derive accounts on it [wireframe](https://www.figma.com/file/aiWZpaXjPLW6fDjE7dpFaU/Projects-2021?node-id=6442%3A5866)
- When creating the seed phrase, the user can export it copied to the clipboard, user has to confirm the saving of the seed phrase [wireframe](https://www.figma.com/file/aiWZpaXjPLW6fDjE7dpFaU/Projects-2021?node-id=6442%3A6015) [wireframe](https://www.figma.com/file/aiWZpaXjPLW6fDjE7dpFaU/Projects-2021?node-id=6442%3A6104)
- Restore accounts from a seed phrase
- Can retrieve a forgotten seed phrase, this requires user to enter the main password

### User accounts

[hifi Designs](https://www.figma.com/file/aiWZpaXjPLW6fDjE7dpFaU/Projects-2021?node-id=5165%3A8862)

- When entering the app, the user is being prompted for a password to decrypt the key pair to be able to perform actions [wireframe](https://www.figma.com/file/aiWZpaXjPLW6fDjE7dpFaU/Projects-2021?node-id=6442%3A5801)
- Can create accounts derived from the master key pair
- Can delete accounts
- User can integrated with Ledger hardware wallet
  - Set up flow TBD
  - Managing TBD
- Can see an overview of the assets in the account and all derived accounts [wireframe](https://www.figma.com/file/aiWZpaXjPLW6fDjE7dpFaU/Projects-2021?node-id=6442%3A5492)
- Can see the details of a single asset, containing the following information [wireframe](https://www.figma.com/file/aiWZpaXjPLW6fDjE7dpFaU/Projects-2021?node-id=6442%3A5681)
  - Balance
  - All past transactions for the current account and asset
  - Button to initiate a new transfer using this asset

### Transfers

[TBD]()

- Can create transparent transfers
- Can create shielded transfers
- Bi-directional transfer between Namada and ETH
  - Supports approving transactions with MetaMask
- Bi-directional transfer between Namada and IBC supported chains
  - Supports approving transactions with Keplr

### Staking & Governance

[TBD]()

- Can bond funds to a list of validators
- Can un-bond funds to a list of validators
- Can submit proposals
- Can vote on proposals
- Can follow up with the current and past proposals and their vote results
