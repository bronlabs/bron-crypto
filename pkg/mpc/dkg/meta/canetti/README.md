# Canetti DKG

Distributed key generation following the CGGMP21 / Canetti et al. line of work,
adapted here to generic monotone access structures represented as MSPs. Each
party acts as a Feldman dealer over the supplied access structure, commits to
its opening material with a hash-based commitment, and proves consistency of the
published verification vector with a batch Schnorr proof. The implementation is
inspired by [Canetti et al., “UC Non-Interactive, Proactive, Threshold ECDSA with
Identifiable Aborts”](https://eprint.iacr.org/2021/060.pdf) and the 2024 revision,
while generalising the sharing layer beyond threshold access structures.

## Protocol Overview

1. **Commit**: Each party samples a random dealer function, computes its Feldman
   verification vector, samples `rho`, creates a batch Schnorr commitment, and
   broadcasts only a hash commitment to the opening material.
2. **Open & Distribute**: Parties open the commitment with
   `CommitmentMessage + witness` and privately send each receiver its share.
3. **Verify & Respond**: Everyone verifies commitments and shares, XORs all
   `rho` values into a common challenge, aggregates the verification vectors and
   shares, and broadcasts the batch Schnorr response.
4. **Finalize**: Parties verify every proof response against the common
   challenge and output an `mpc.BaseShard` containing the aggregated share and
   verification vector.

## Implementation Notes

- The protocol uses `sharing/vss/meta/feldman`, so the resulting shard is tied
  to the MSP induced by the provided access structure.
- `rho` length and the batch Schnorr challenge length both scale with the MSP
  dimension `D`, matching the batched proof soundness requirements.
- `Participant` exposes the round API directly; `NewRunner` wraps the same logic
  behind a `network.Runner`.

## Usage

1. Build a `session.Context` for each party and choose a monotone access
   structure.
2. Create a `Participant` with `NewParticipant`, or use `NewRunner` for
   fully-managed execution over a `network.Router`.
3. Exchange `Round1Broadcast`, then `Round2Broadcast` plus `Round2P2P`, then
   `Round3Broadcast`.
4. Call `Round4` to obtain the final `mpc.BaseShard`.
