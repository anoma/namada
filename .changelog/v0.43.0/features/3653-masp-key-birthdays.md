 - Partially addresses Issue [\#2900](https://github.com/anoma/namada/issues/2900). Viewing and spending keys can now
   be given birthdays in the form of block heights which are loaded into 
   shielded sync. Shielded sync will not try to decrypt a block before a 
   keys birthday with said key. ([\#3653](https://github.com/anoma/namada/pull/3653))