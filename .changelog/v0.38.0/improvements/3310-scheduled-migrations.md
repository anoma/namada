- Allow nodes to schedule a migrations json to be read and run to facilitate hard-forking. This is done by 
  taking a migrations json and passing the path, a hash of the contents, and a block height to the node when 
  starting the ledger. ([\#3310](https://github.com/anoma/namada/pull/3310))