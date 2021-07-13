# Topic

A topic is string and a encoding that describes this sub-network. In a topic all
intents use the exact same encoding. That encoding is known by matchmakers so it
can match them. Whenever a node subscribes to a new topic it informs all
connected nodes and each of them propagate it. With this it’s easy to create new
topics in the intent gossip network and inform others.

A node opt-in to a propagated new topic with the help of a filter. This filter
is define as a combination of a whitelist, a regex expression, and a maximum
limit.
