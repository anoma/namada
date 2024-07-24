 - Implements phase 1 of Issue [\#3385](https://github.com/anoma/namada/issues/3385)
   - When fetching notes, connections and related failures should not halt shielded sync. Instead, the process
     should be restarted
   - If fetching is interrupted, the data fetched should be persisted locally so that progress isn't lost.
   -  A trait for fetching behavior should be added to provide modularity

      ([\#3498](https://github.com/anoma/namada/pull/3498))
