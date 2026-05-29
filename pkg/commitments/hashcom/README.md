# Hash-Based Commitments

This package implements a non-interactive commitment scheme built from a keyed
hash. It is computationally hiding and computationally binding, and unlike
Pedersen commitments it commits to arbitrary byte strings, is not homomorphic,
and has no trapdoor (commitments cannot be equivocated).

## Overview

- Public parameter: a `CommitmentKey` `k` (32 bytes) that keys the hash. It is
  not a secret — binding and hiding hold even when an adversary knows `k`.
- Commitment to message `m` with witness `w`: `C = H_k(m || w)`, where `H_k` is
  BLAKE2b-256 in its native keyed (MAC) mode and `w` is a fresh 256-bit nonce.
- **Binding** reduces to the collision resistance of the keyed hash. The witness
  is fixed size and appended last, so the `(m, w)` split is unambiguous and the
  input encoding is injective; opening one commitment to two distinct messages
  therefore requires a hash collision. With a 256-bit digest this gives λ=128
  bits of security against birthday collisions.
- **Hiding** rests on the secret witness: with `w` unknown and drawn with full
  256-bit entropy, `H_k(m || w)` is pseudorandom and reveals nothing about `m`.
- All types implement fixed-length CBOR encoding for transport and persistence;
  decoding rejects inputs that are not exactly the expected length.

## Types

- `CommitmentKey`: the public 32-byte hash key.
- `Message`: the arbitrary byte string being committed (`[]byte`).
- `Witness`: the secret 32-byte opening nonce. Must stay private until opening.
- `Commitment`: the 32-byte keyed-hash digest that is published.

## Key Generation

The commitment key is a public parameter and may be shared freely. Obtain one via:

- `SampleCommitmentKey(prng)`: draws a uniformly random key from `prng`.
- `ExtractCommitmentKey(transcript, label)`: derives the key deterministically
  from a public transcript (Fiat–Shamir style), so all parties agree on the same
  key without a separate setup. The `label` domain-separates the key from other
  extractions on the same transcript.

## Algorithms

- **CommitWithWitness(message, witness)**: deterministic commitment
  `H_k(message || witness)` using caller-supplied randomness.
- **SampleWitness(prng)**: draws a fresh 256-bit opening nonce. Use a
  cryptographically secure `prng`; a reused or low-entropy witness breaks hiding.
- **Open(commitment, message, witness)**: recomputes the commitment and compares,
  returning `commitments.ErrVerificationFailed` on mismatch.

The package-level `commitments.Commit` helper combines `SampleWitness` and
`CommitWithWitness` to produce a `(commitment, witness)` pair in one call.
