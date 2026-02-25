# PRZS Seed Setup

Commit-and-reveal setup for pairwise seeds used by the PRZS sampler.

## Protocol Overview

1. **Commit**: Each party samples per-peer seed contributions, commits to them, and broadcasts the commitments.
2. **Open**: Parties open their commitments privately to each peer, providing decommitment witnesses.
3. **Derive Seeds**: Peers verify openings and XOR contributions to derive symmetric pairwise seeds.

## Implementation Notes

- Hash-based commitments bind seed contributions; verification failures abort with the sender’s ID.
- Transcript key material is extracted via `transcripts` for deterministic commitment keys.
- `Participant` exposes `Round1`, `Round2`, `Round3` for message exchange via `network.Router`.

## Usage

1. Construct a setup participant with `NewParticipant(sessionID, id, quorum, tape, prng)`.
2. Run `Round1` to broadcast commitments.
3. Run `Round2` to send openings privately to each peer.
4. Run `Round3` with received openings to obtain pairwise `przs.Seeds` for the PRZS sampler.
