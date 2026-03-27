# Share Redistribution

Verifiable share redistribution protocol for moving a secret from an existing
qualified set of shareholders to a new linear access structure without
reconstructing the secret centrally.

This package follows the subshare-based verifiable redistribution approach from
[“Verifiable Secret Redistribution for Threshold Sharing Schemes”][1]
by Wong and Wing, adapted to the repository’s Feldman-style verification and
MSP-based sharing types.

## Protocol Overview

1. **Qualified Recoverers**: A qualified subset of holders under the previous access structure acts as recoverers.
   Each recoverer starts from a valid old share and its verification vector.
2. **Subshare Redistribution**: In `Round1`, every recoverer converts its old share into an additive share
   over the recoverer set, blinds it with a zero share, then redistributes that value as a fresh verified sharing
   under the next access structure.
3. **Verification & Aggregation**: Each recoveree verifies every received subshare against 
   the recoverer’s broadcast verification material, sums the verified subshares, and combines the verification vectors.
4. **Consistency Check**: The resulting verification vector must preserve the original secret commitment,
   ensuring the redistributed shard represents the same underlying secret under the new access structure.

## Implementation Notes

- The implementation separates the old and new structures: `recoverers` must be qualified under the previous shard’s MSP,
  while `nextAccessStructure` defines the redistributed shard.
- Verification is two-layered, matching the paper’s main idea: recoverees validate both the recoverers’ old-share commitment
  and the newly distributed subshares.
- The session quorum must equal the union of the recoverer set and the shareholders of the next access structure.
- `Participant` exposes `Round1` and `Round2`; use a `network.Router` or equivalent transport to exchange broadcasts and unicasts.

## Usage

1. Build a `session.Context` whose quorum contains exactly the recoverers and the shareholders in the next access structure.
2. For each party, call `NewParticipant(ctx, recoverers, prevShard, nextAccessStructure, prng)`.
3. Recoverers call `Round1` and send the resulting `Round1Broadcast` plus per-recipient `Round1P2P` messages.
4. Recoverees collect the round-1 messages and call `Round2` to obtain a `BaseShard` for the redistributed secret.

[1]: <https://www.cs.cmu.edu/~wing/publications/Wong-Wing02b.pdf>