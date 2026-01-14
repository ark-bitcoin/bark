
Offboard Swaps
==============


# Motivation

Offboards can happen in Ark rounds.
In traditional Ark or clArk rounds, offboards are very practical:
the server simply adds an output to the round's funding tx and because
the connectors commit to the entire funding tx, users commit to the offboard
in their forfeit tx.

With hArk, however, forfeits only commit to a single unlock preimage/hash.
This unlock hash guards the release of the newly issued VTXOs. However, there
is no longer an automatic commit to the entire funding tx as well.
This means that in order to implement offboards in hArk, an additional
hash-based condition must be placed on the offboard output, making them
significantly less attractive because an additional on-chain tx must be made in
order to actually send the funds to the desired on-chain address.


# Hash-locked Swaps

An alternative offboard mechanism to in-round offboards is to directly swap
your input VTXOs with an on-chain output.

The traditional or naive approach to accomplish this would be for the server
to send the desired on-chain amount to a hash-locked output, then the user would
sign a forfeit tx that forces the server to reveal the preimage, so that the
user can unlock the funds in the on-chain output.

However, in this simple hash-based swap approach, the user still requires an
additional on-chain tx to unlock their funds.


# Connector Swaps

An alternative swap technique that can be used is a connector swap.

The server creates an offboard tx that delivers the offboard to the user, and
adds an additional connector output to this tx.
(In theory the change output could also function as the connector output so
that no additional output has to be created.)

Before the server signs this tx, the user signs a forfeit tx that is only valid
when spent with the connector output of the offboard tx. Once the server has
the user's signature on this forfeit tx, it can sign and broadcast the offboard
tx.


# Implementation

Implementing connector swaps for offboards would mean that offboards can happen
instantly without the user requiring to wait for a round.

The following changes must be made to the server:
* Additional gRPC endpoints must be created to facilitate offboard requests and
forfeit signature exchange.
* Either a dedicated offboard wallet must be created or precautions must be
implemented to ensure unconfirmed offboard tx chains don't grow too old to
impede proper round function.
* Round-based offboards can then be entirely deprecated.
