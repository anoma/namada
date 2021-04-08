# Orderbook filter

The orderbook is define with a intent filter. It is gossiped to any attach peers
and is bounded in size and runtime. To send an intent to peers, it must pass its
corresponding filter. When receiving an intent the orderbook checks the filter,
if the filter does not validate the intent then the peer score is lowered until
a threshold and getting ban.

