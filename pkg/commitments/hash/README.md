# Hash-Based Commitments

This package provides a simple, non-homomorphic commitment scheme built from a keyed BLAKE2b-256 hash (HMAC-style). A random witness is mixed with the message and keyed hash to produce a binding digest.

## Overview

- Commitment to `message` with randomness `witness`: `C = HMAC_key(witness || message)` using BLAKE2b-256 by default.
- Key is derived from a session identifier (SID), domain separation tag, and optional CRS transcripts.
- Witness randomness is always 32 bytes; the resulting commitment digest is 32 bytes.
- All types are Go value types suitable for copying and CBOR/binary transport via their byte representations.

## Types

- `Key`: 32-byte secret key for the HMAC; derive with `NewKeyFromCRSBytes`.
- `Message`: arbitrary byte slice to commit.
- `Witness`: 32-byte nonce mixed into the commitment.
- `Commitment`: 32-byte digest output.
- `Scheme`: convenience wrapper exposing a committer and verifier bound to a `Key`.

## Algorithms

- **NewKeyFromCRSBytes(sid, dst, crs...)**: derives the commitment key from the SID, domain separation tag, and optional CRS blobs.
- **Commit(message, prng)**: samples a fresh witness from `prng`, returns `(commitment, witness)`.
- **CommitWithWitness(message, witness)**: deterministic commitment using caller-provided randomness.
- **Verify(commitment, message, witness)**: recomputes the digest and checks equality.

## Notes

- `HmacFunc` is configurable for testing; it defaults to `blake2b.New256`.
- The scheme is computationally binding and hiding assuming the PRF security of the keyed hash and the unpredictability of the witness.
