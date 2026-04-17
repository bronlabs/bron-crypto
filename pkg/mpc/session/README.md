# Session Setup Protocol

## Description
The setup protocol must run before other higher-level MPC protocols (DKG, threshold signing, etc.).

Its job is to build a shared session foundation:
1. A common `SessionID` for domain separation.
2. A synchronized transcript root that all parties derive in the same way.
3. Deterministic pairwise seeds between each pair of parties.

Those pairwise seeds are then reused by other building blocks, including additive zero-share sampling,
sub-context derivation, and transcript-scoped randomness.

Higher-level protocols need consistent shared context, but without introducing a dealer.
This setup gives each party:
1. The same session identity and transcript initialization.
2. Independent pairwise pseudorandom streams with every other participant.
3. Deterministic behavior under identical protocol transcripts.

Without this step, downstream protocols would either:
1. Depend on ad-hoc randomness plumbing.
2. Risk transcript/domain collisions across protocol instances.
3. Lose the ability to derive correlated values (like zero-sum additive shares) safely and reproducibly.

## Spec
### Session Setup
The protocol runs in four rounds.

1. Round 1:
   Each party samples:
   - a per-recipient commitment key
   - a common random contribution
   It commits to the common contribution under the fixed common commitment key and broadcasts:
   - the commitment key
   - the common contribution commitment
2. Round 2:
   After receiving every other party's round-1 broadcast, each party:
   - stores the peers' commitment keys
   - samples a fresh pairwise contribution for every peer
   - commits to each pairwise contribution under the recipient's commitment key
   It then:
   - broadcasts the common contribution opening
   - unicasts the pairwise contribution commitments
3. Round 3:
   Each party verifies every peer's common contribution opening against the round-1 common commitment,
   stores the received pairwise contribution commitments, and unicasts the openings of its own pairwise contributions.
4. Round 4:
   Each party verifies every received pairwise contribution opening against the corresponding round-2 commitment 
   and then derives:
   - the common session seed from the sorted quorum, commitment keys, common commitments, common contribution openings,
     and common contribution witnesses
   - a symmetric pairwise seed with every peer by hashing the common session seed together with
     the two verified pairwise contributions in deterministic ID order
   Finally, the party constructs the session context from that common seed and the pairwise seeds.

## Security and Correctness Notes
1. Deterministic sorted quorum ordering is required for all hash/concat operations.
2. The final common session seed is bound to both the common commitments and their verified openings, not just to the opened values.
3. Commitment keys are per-recipient, so every pairwise opening is verified against a recipient-local commitment key.
4. Pairwise seed construction is symmetric by ID ordering, ensuring both sides derive identical material.
5. Domain separators prevent collisions between setup, seed derivation, and sub-context derivation.
