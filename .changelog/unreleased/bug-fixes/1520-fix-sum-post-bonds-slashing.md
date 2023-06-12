- When processing slashes, bonds and unbonds that became active after
  the infraction epoch must be properly accounted in order to properly
  deduct stake that accounts for the precise slash amount. A bug
  is fixed in the procedure that properly performs this accounting.
  ([#1520](https://github.com/anoma/namada/pull/1520))