# Share Redistribution

Verifiable share redistribution protocol for moving a secret from an existing
qualified set of shareholders to a new linear access structure without
reconstructing the secret centrally.

This package follows the subshare-based verifiable redistribution approach from
[“Verifiable Secret Redistribution for Threshold Sharing Schemes”][1]
by Wong and Wing, adapted to the repository’s Feldman-style verification and
MSP-based sharing types.

Note that the following protocols are special cases of this protocol:

1. **Refresh** If `prevShareholders` is exactly equal the shareholders of the `nextAccessStructure`'s shareholder set (provided that `nextAccessStructure` is equal to the current access structure), then the resulting protocol is a refresh protocol.
2. **Recovery Followed By Refresh** If `nextAccessStructure` is equal to the current access structure, but some shareholders are missing from `prevShareholders`, then the resulting protocol is a recovery+refresh protocol.

## Protocol Overview

1. **Qualified Previous Shareholders**: A qualified subset of holders under the previous access structure.
   Each shareholder starts from a valid old share and its verification vector.
2. **Zero-Sharing Setup**: In `Round1`, previous shareholders run round 1 of the HJKY interactive zero-sharing protocol
   within the previous-shareholder set.
3. **Subshare Redistribution**: In `Round2`, every previous shareholder converts its old share into an additive share
   over the previous shareholder set, blinds it with the HJKY zero share, redistributes that value as a fresh verified
   sharing under the next access structure, and sends the resulting metadata and private contributions.
4. **Verification & Aggregation**: In `Round3`, each next shareholder verifies every received contribution against the
   broadcast verification material, sums the verified contributions, and combines the verification vectors.
5. **Consistency Check**: The resulting verification vector must preserve the original secret commitment,
   ensuring the redistributed shard represents the same underlying secret under the new access structure.

## Implementation Notes

- The implementation separates the old and new structures: `prevShareholders` must be qualified under the previous shard’s MSP,
  while `nextAccessStructure` defines the redistributed shard.
- Verification is two-layered, matching the paper’s main idea: next shareholders validate both the old-share commitment
  and the newly distributed subshares.
- `trustedAnchorID` can be used to support identifiable aborts. Whenever previous shareholders provide metadata that must agree
  globally, the protocol compares all such values against the message from this trusted previous shareholder and attributes
  inconsistencies to the offending sender. If no trusted anchor is configured, the protocol still performs non-identifiable
  consistency checks before returning a shard.
- The session quorum must equal the union of the previous shareholders and shareholders of the next access structure.
- `Participant` exposes `Round1`, `Round2`, and `Round3`; use a `network.Router` or equivalent transport to exchange broadcasts and unicasts.

## Usage

1. Build a `session.Context` whose quorum contains every participant in the protocol.
2. Optionally choose a `trustedAnchorID` from `prevShareholders`. This party acts as the trust anchor for identifiable-abort checks on
   shared verification metadata. If you omit it, the protocol still checks aggregate consistency but some metadata failures become
   non-identifiable aborts.
3. For each party, call `NewParticipant(ctx, prevShareholders, prevShard, nextAccessStructure, prng, opts...)`.
   If you want identifiable-abort support for metadata inconsistencies, pass `redistribute.WithTrustedAnchorID(trustedAnchorID)`.
4. Previous shareholders call `Round1` and send the resulting `Round1Broadcast` plus per-recipient `Round1P2P` HJKY messages.
5. Previous shareholders collect the round-1 messages and call `Round2` to produce a `Round2Broadcast` and per-recipient `Round2P2P` redistribution messages.
6. Next shareholders collect the round-2 messages and call `Round3` to verify, aggregate, and obtain a `BaseShard` for the redistributed secret.

[1]: <https://www.cs.cmu.edu/~wing/publications/Wong-Wing02b.pdf>
