# signing

Interactive signing protocol for Lindell22 Schnorr over arbitrary monotone access structures.

## Overview

Implements the 3-round interactive signing protocol from Lindell 2022. Each round involves broadcasting messages to all parties in the signing quorum.

## Protocol Rounds

1. **Round 1**: Sample random nonce, commit to it, broadcast commitment
2. **Round 2**: Receive commitments, broadcast nonce with discrete log proof
3. **Round 3**: Verify commitments and proofs, compute partial signature

## Identifiable Abort

When the aggregated signature fails verification, the aggregator enters an
identification phase that attempts to determine which party misbehaved.

**Cosigning aggregator** (`NewCosigningAggregator`): the aggregator is also a
participant in the signing session. Because it executed rounds 1-3 itself, it
retains the correct aggregated nonce commitment R and each party's individual
(parity-corrected) nonce commitment from round 2. During aggregation it can:

- Use the known R instead of re-deriving it from partial signatures.
- Cross-check each partial signature's R against the committed value, catching
  any party that substituted a different nonce.
- Enter the full identification phase to verify each partial signature against
  the party's additive public key share, catching parties that used an
  incorrect secret key share.

**Non-cosigning aggregator** (`NewAggregator`): the aggregator is a third party
that did not participate in the signing rounds. It has no independent knowledge
of R or the individual nonce commitments and must derive R by summing the R
values from partial signatures. A malicious signer can add a random δ to both
its R and S values; the resulting partial signature is internally
self-consistent (individually verifiable) but corrupts the aggregated R. The
aggregator detects the failure — the recomputed challenge no longer matches —
but **cannot attribute blame** because every partial signature carries the
original (now stale) challenge. The protocol aborts without identifying the
culprit.
