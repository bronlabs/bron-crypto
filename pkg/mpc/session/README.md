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
1. Each party samples and broadcasts a commitment key.
2. Using receiver's keys, each party commits to a fresh per-peer contribution and sends commitments to it.
3. Each party opens its contributions.
4. Each party verifies received openings against stored commitments.
5. For every peer pair, both sides derive the same pairwise seed by concatenating the two verified contributions in deterministic ID order.
6. Parties use these pairwise seeds (plus common setup data) to build the session context (session ID + transcript initialization).

## Security and Correctness Notes
1. Deterministic sorted quorum ordering is required for all hash/concat operations.
2. Commitment keys are per-recipient, so every opening is verified against recipient-local commitment key.
3. Pairwise seed construction is symmetric by id-ordering, ensuring both sides derive identical material.
4. Domain separators prevent collisions between setup, seed derivation, and sub-context derivation.
