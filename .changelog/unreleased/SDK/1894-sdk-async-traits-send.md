- Added the `Send` bound to the `Client` and `ShieldedUtils` `async_trait`s'.
  This allows the SDK to be used in environments which are both asynchronous and
  multithread. ([\#1894](https://github.com/anoma/namada/pull/1894))