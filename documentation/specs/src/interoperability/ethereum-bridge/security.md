# Security

On Namada, the validators are full nodes of Ethereum and their stake is also
accounting for security of the bridge. If they carry out a forking attack
on Namada to steal locked tokens of Ethereum their stake will be slashed on Namada.
On the Ethereum side, we will add a limit to the amount of assets that can be
locked to limit the damage a forking attack on Namada can do. To make an attack
more cumbersome we will also add a limit on how fast wrapped Ethereum assets can
be redeemed from Namada. This will not add more security, but rather make the 
attack more inconvenient.
