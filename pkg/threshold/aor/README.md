# Agree on Random (AOR)

Protocol for distributively sampling a random value: all parties contribute randomness, and everyone outputs the XOR if and only if all openings verify. Implemented with hash-based commitments and three broadcast rounds.

## Protocol Overview

1. **Commit**: Each party samples a random seed `r_i` and broadcasts a commitment.
2. **Open**: Parties broadcast `(r_i, witness_i)` openings for their commitments.
3. **XOR Aggregate**: After verifying all openings, parties XOR all `r_i` values to obtain the joint random output. Any failed verification aborts.

## Implementation Notes

- Commitments use the hash-based scheme from `pkg/commitments/hash`.
- Transcript binding via `transcripts` ensures domain separation and reproducibility.
- `Participant` exposes `Round1`, `Round2`, `Round3`; use a `network.Router` to exchange round messages.

## Usage

1. Construct a `Participant` with `NewParticipant(id, quorum, size, transcript, prng)`.
2. Run `Round1` to produce a `Round1Broadcast` commitment.
3. Collect others’ commitments; call `Round2` to produce the opening.
4. Collect openings; call `Round3` to verify and derive the shared random output (byte slice of length `size`).
