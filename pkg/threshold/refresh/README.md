# Share Refresh

Proactive share refresh protocol following [“Proactive Secret Sharing”](https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf). 
arties derive a zero-sum sharing and add it to their existing Feldman shares,
obtaining fresh shares of the same secret.

## Protocol Overview

1. **Zero Sharing**: Run the HjKY zero-sharing subprotocol to generate a shared random value that sums to zero.
2. **Apply Offset**: Each party adds its zero share to its current share
   and adds the corresponding verification vector to the existing one.
3. **Output**: Refreshed shares and verification material represent the same secret under fresh randomness.

## Implementation Notes

- Refreshing does not alter the underlying secret or access structure.
- The transcript domain separator binds the refresh session to the caller’s context.
- `Participant` exposes `Round1` and `Round2`; use a `network.Router` to exchange messages.

## Usage

1. Create a refresher with `NewParticipant(sessionID, shard, tape, prng)`.
2. Run `Round1` and exchange `Round1Broadcast`/`Round1P2P` messages.
3. Run `Round2` with collected inputs to obtain the refreshed share and verification vector.
