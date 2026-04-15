# HJKY Zero Sharing

Zero-sum sharing protocol.
Parties jointly generate Feldman shares whose sum is zero,
enabling share refresh without changing the underlying secret.

## Protocol Overview

1. **Zero Deal**: Each party deals a Feldman sharing of zero and broadcasts the verification vector.
2. **Verify**: Parties verify received zero-shares against the broadcast vectors.
3. **Aggregate**: All zero-shares and verification vectors are added to obtain
   a joint zero-share and combined verification material.

## Implementation Notes

- Verification vectors are written to the transcript to bind refresh sessions.
- Invalid shares trigger an abort tagged with the sender’s identifier.
- `Participant` exposes `Round1` and `Round2` for orchestration via `network.Router`.

## Usage

1. Create a participant with `NewParticipant(ctx, accessStructure, group, prng)` — the holder ID is taken from the session context.
2. Run `Round1` to produce `Round1Broadcast` and unicasts of zero-shares.
3. Exchange messages, then run `Round2` to get the aggregated zero-share and verification vector.

## Reference

- [Proactive Secret Sharing Or: How to Cope With Perpetual Leakage](https://link.springer.com/chapter/10.1007/3-540-44750-4_27)
