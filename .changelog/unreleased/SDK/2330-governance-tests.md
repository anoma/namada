- Added `QueryProposalVotes` struct. Removes `VoteType`from
  the `Display` implementation of `LedgerProposalVote`. Updates
  `build_vote_proposal` to return an error if voter has no delegations.
  ([\#2330](https://github.com/anoma/namada/pull/2330))