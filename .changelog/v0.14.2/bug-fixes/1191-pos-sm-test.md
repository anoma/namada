- Fixed an issue in which a validator's stake and validator sets
  data gets into an invalid state (duplicate records with incorrect
  values) due to a logic error in clearing of historical epoch data.
  ([#1191](https://github.com/anoma/namada/pull/1191))