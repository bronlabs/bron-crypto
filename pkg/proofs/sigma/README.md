# Sigma protocol

This package defines a generic interface for sigma protocols and interactive compiler for running it
in round-based setup where:

* Round 1: $P$ computes commitment $a$ and sends it to $V$, stores the state $s$ locally, 
* Round 2: $V$ randomly create a challenge $e$ and sends it to $P$,
* Round 3: $P$ computes response $z$ and sends to $V$,
* $V$ performs verification.

Additionally, the `RunHonestVerifierZkSimulator` method is defined.
In the context of Honest-Verifier Zero-Knowledge Proofs of Knowledge, the simulator is an algorithm
that is able to fake a commitment and a convincing proof without knowledge of the witness.
In order to fake it, the simulator does things in reverse order (a.k.a. "rewinds"): first create a proof/response,
and then compute the commitment intelligently so that the full interaction would be valid if played in the right order.

The method is needed because the OR composition of proofs requires a valid simulator for the proof generation,
that is, in order to generate a proof for $x_0$ OR $x_1$ we must know how to convincingly simulate the one
we don't know and thus can't prove knowledge of!

See [CDS94] for details.

## WARNING
treat compositions and compilers with care as what’s programmatically allowed
isn’t going to be necessarily secure or preserve the security of the larger protocol.

[CDS94]: <https://link.springer.com/chapter/10.1007/3-540-48658-5_19>
