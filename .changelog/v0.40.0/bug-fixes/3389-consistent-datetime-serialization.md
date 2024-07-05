- Our `DateTimeUtc` type allowed a relaxed representation of RFC3339 strings.
  We now enforce a string subset of this format, to guarantee deterministic
  serialization. ([\#3389](https://github.com/anoma/namada/pull/3389))