## Persistence of User Wallet

The state of the user's wallet, consisting of their master seed, along with any accounts derived from that seed, should be stored locally in a safe manner. As this requires the use of `localStorage`, all data should be encrypted.

Presently, this challenge is being addressed by using the user's password (specified when creating their master seed) to encrypt/decrypt the mnemonic seed, as well as unlocking the state of their wallet. The accounts in the state are being persisted via [redux-persist](https://github.com/rt2zz/redux-persist), with an [ecryption transform](https://github.com/maxdeviant/redux-persist-transform-encrypt) that handles the encrypting and decrypting of all data stored in `localStorage`.

The mnemonic is stored separately from the accounts data. In `namada-apps/packages/namada-lib/lib/types/mnemonic.rs` implementation of `Mnemonic`, we provide the ability to specify a password allowing us to retrieve a storage value of the mnemonic, which is encrypted before saving to `localStorage`. When the wallet is locked, the user must provide a password, which is validated by attempting to decrypt the stored mnemonic. If successful, the password is used to either generate an encrypted Redux persistence layer, or decrypt the existing one, restoring the user's wallet state.

`redux-persist` gives us the ability to specify which sub-sections of the state should be persisted. Presently, this is only enabled for any derived account data. From the persisted store, we can establish a `persistor`, which can be passed into a `PersistGate` component that will only display its children once the state is retrieved and decrypted from storage.

If we wanted to export the state of the user's accounts, this would be trivial, and simply a matter of exporting a JSON file containing the `JSON.stringify`ed version of their accounts state. Some work would need to be done in order to restore the data into Redux, however.

The `localStorage` state is stored in one of three places, depending on your environment:

- `persist:namada-wallet` - Production
- `persist:namada-wallet-dev` - Devnet
- `persist:namada-wallet-local` - Local ledger

This allows us to keep our wallet state in sync with multiple ledgers while testing.

## Restoring the accounts state from file

The user should have the ability to save the state of their accounts in their wallet to a JSON file. It is relatively trivial to take a snapshot of the accounts state once the user is authenticated.

Technically, this will likely involve a process by which, following the upload of the file and successful parsing, the existing `persist:namada-wallet` storage is cleared, and when the store is initialized, we pass the parsed accounts state in to `configureStore` by way of the `preloadedState` parameter. This will only happen once, and on subsequent calls to the `makeStore` function, it should hydrate from the encrypted value in local storage.

Refer to the following to see how our present `makeStore` Redux store factory functions:

https://github.com/heliaxdev/namada-apps/blob/9551d9d0f20b291214357bc7f4a5ddc46bdc8ee0/packages/namada-wallet/src/store/store.ts#L18-L50

This method currently accepts a `secretKey` as required by the `encryptTransform`, and checks the environment variables `REACT_APP_LOCAL` and `NODE_ENV` to determine where the store gets saved in `localStorage`. This is mostly useful for local testing where you may want to switch between connecting to a local ledger or a testnet, and want to keep your local stores in sync with both.

## Challenges

As a secret is required to unlock the persisted store, this store must be instantiated dynamically once a password is entered and validated. In the current implementation of the wallet, any routes that will make use of the Redux store are loaded asynchronously. When they are loaded, the store is initialized with the user's password (which is passed in through the Context API in React, separate from the Redux state).

## Resources

- [redux-persist](https://github.com/rt2zz/redux-persist) - Redux store persistence
- [redux-persist-transform-encrypt](https://github.com/maxdeviant/redux-persist-transform-encrypt) - Transform to encrypt persisted state
- [Notes on initial data in Redux](https://dev.to/lawrence_eagles/how-to-properly-set-initial-state-in-redux-78m)
- [Notes on clearing persisted Redux state](https://bionicjulia.com/blog/clear-redux-toolkit-state-with-redux-persist-and-typescript)
