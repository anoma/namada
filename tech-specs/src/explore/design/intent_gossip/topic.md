# Topic

A topic is string and a encoding that describes this sub-network. In a topic all
intents must use the exact same encoding. That encoding is known by matchmakers
so it can match them.  Whenever a node subscribes to a new topic it informs all
connected nodes. Each of them tries to subscribe to it and continue the
propagation of that new topic. With this it’s easy to create new topics in the
intent gossip network and inform others.

To prevent spamming of topic creation, each node can define a topic filter. This
filter prevents subscribing to a topic that the user is not interested in. This
filter is a combination of a whitelist, a regex expression, and a maximum limit
of subscribed topics.
