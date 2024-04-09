- Some transactions now use temporary storage (only kept for the duration of
  the tx execution and VPs validation) to indicate what actions were applied to
  validity predicates that use the information to decide who has to authorize
  the transaction. ([\#2934](https://github.com/anoma/namada/pull/2934))