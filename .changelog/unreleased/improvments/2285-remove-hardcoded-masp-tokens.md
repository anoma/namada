- Previously, a hardcoded set of tokens were expected to be used in Masp conversions.
  If these tokens did not have configs in genesis, this would lead to a panic after the first
  epoch change. This PR fixes this to use the tokens found in genesis belonging to the MASP
  rewards whitelist instead of hardcoding the tokens.
  ([\#2285](https://github.com/anoma/namada/pull/2285))