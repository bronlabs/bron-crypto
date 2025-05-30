# Refresh
The refresh is essentially the same as DKG but every party does sharing of zero (which is then validated by other parties).
The respective zero shares of $d_1$ and $d_2$ are then added to the shard.
This is basically the same as refresh of elliptic curve based refresh but the integer replicated secret sharing is used.
The outline of the protocol is:

Round 1:
* share zero
* broadcast commitments to shares and the proof that shares open to zero
* send shares to respective parties

Round 2:
* receive the share, commitments and the proof
* validate the proof
* update the shard with the received share
