## Using JSON RPC to Communicate with Ledger

To query values from the ledger, the web-wallet must issue JSON RPC calls to the **Tendermint** `abci_query` endpoint over HTTP, which if running the ledger locally, would look like:

```
http://localhost:26657/abci_query/
```

Similarly, when broadcasting transactions, we must communicate with the ledger over websockets to an endpoint such as:

```
ws://localhost:26657/websocket/
```

To handle this in the wallet, we can make use of existing functionality from `cosmjs`, namely, the `RpcClient` and `WebsocketClient`.

### RPC HTTP Client

Over HTTP, using the `abci_query` endpoint, we can query the ledger by providing a `path` to the storage value we wish to query. Here are some examples:

- Query balance: `value/#{token_address}/balance/#{owner_address}`
- Query epoch: `epoch`
- Is known address?: `has_key/#{address}/?`

There are many other types of queries in addition to `abci_query` that can be issued to Tendermint. See [https://docs.tendermint.com/master/rpc/](https://docs.tendermint.com/master/rpc/) for more information.

### WebSocket Client

The most interesting type of interaction with the ledger thus far is via WebSockets. The goal of the implementation in `anoma-wallet` is to allow us to provide listeners so that we can update the React app according to activity on the ledger. The core functionality of the implementation on the client is as follows:

```ts
public async broadcastTx(
  hash: string,
  tx: Uint8Array,
  { onBroadcast, onNext, onError, onComplete }: SubscriptionParams
): Promise<SocketClient> {
  if (!this._client) {
    this.connect();
  }

  try {
    const queries = [`tm.event='NewBlock'`, `${TxResponse.Hash}='${hash}'`];
    this.client
      ?.execute(
        createJsonRpcRequest("broadcast_tx_sync", { tx: toBase64(tx) })
      )
      .then(onBroadcast)
      .catch(onError);

    this.client
      ?.listen(
        createJsonRpcRequest("subscribe", {
          query: queries.join(" AND "),
        })
      )
      .addListener({
        next: onNext,
        error: onError,
        complete: onComplete,
      });

    return Promise.resolve(this);
  } catch (e) {
    return Promise.reject(e);
  }
}
```

There are a few key things happening here. Once we have constructed a transaction, we receive a transaction `hash` and a `Uint8Array` containing the bytes of the wrapped and signed transaction. We first execute the request to `broadcast_tx_sync`, which can take an `onBroadcast` callback from the client to listen to the initial response from the ledger. We provide the `tx` data in `base64` format as an argument.

Following that, we subcribe to events on the ledger using a query containing `tm.event='NewBlock' AND applied.hash='transaction_hash_value'`, then then register the following listeners so that we may trigger activity in the front-end app:

- `onNext` - called when we receive a `NewBlock` event that matches our `hash`
- `onError` - called in the event of an error
- `onComplete` - called when the websocket closes

The way this library in `anoma-wallet/src/lib/` is implemented, we can also determine when we want to disconnect the WebSocket. For instance, if for some reason we want to issue a series of transactions in succession, we could feasibly leave the connection open, then close after the final transaction is complete. Alternatively, and in most cases, we would simply close the connection when we are finished with a single transaction, which would then trigger the `onComplete` callback.

See [Transparent Transactions](./transparent-transactions.md) for more information on how the transactions are initially constructed.
