# Share Recovery

Protocol for reconstructing a missing party’s Feldman share as described in [“Proactive Secret Sharing”](https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf).
Parties collaboratively blind a fresh sharing, offset it to the missing index,
and interpolate the blinded shares to restore the lost value.

## Protocol Overview

1. **Blind Sharing**: Helpers deal a random Feldman sharing and broadcast the blinded verification vector
   while sending blinded shares privately.
2. **Offset & Verify**: Helpers adjust the blinded shares to include their current share of the secret,
   reusing the original verification vector.
3. **Interpolate**: The mislayer checks consistency, interpolates the blinded shares at its index,
   and verifies against the published verification vector.

## Implementation Notes

- Blinding hides the original secret while enabling additive reconstruction of the missing share.
- Verification vectors ensure correctness of each helper’s contribution; invalid shares abort the protocol.
- `Recoverer` runs Round1/Round2 for helpers; `Mislayer` runs Round3 to reconstruct and verify.

## Usage

1. Instantiate helpers with `NewRecoverer(mislayerID, quorum, shard, prng)` and the mislayer with `NewMislayer`.
2. Helpers call `Round1` and exchange `Round1Broadcast`/`Round1P2P` messages.
3. Helpers call `Round2` to produce `Round2Broadcast`/`Round2P2P`; deliver to mislayer.
4. The mislayer calls `Round3` to obtain the recovered share and verification vector.
