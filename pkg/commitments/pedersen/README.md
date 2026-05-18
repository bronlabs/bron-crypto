# Pedersen Commitments

Pedersen commitments are perfectly hiding and computationally binding (under the discrete logarithm assumption) over a prime-order group. This package implements a two-generator instantiation with additive homomorphism and re-randomisation support.

## Overview

- Common reference string: two generators `g` and `h` of the same prime-order group, where the discrete-log relation between them is unknown.
- Commitment to scalar message $m$ with randomness $r$: $C = g^m \cdot h^r$.
- Additive homomorphism: multiplying commitments corresponds to adding messages; commitments can be re-randomised without changing the message.
- All types implement CBOR encoding for transport and persistence.

## Types

- `Key`: holds generators `g` and `h`.
- `Message`: wraps the scalar message in the group’s field.
- `Witness`: randomness used to hide the message.
- `Commitment`: prime-group element representing $g^m \cdot h^r$.
- `Scheme`: wires the committer and verifier around a fixed `Key`.

## Key Generation

Pedersen binding fails if a committer knows a scalar `s` such that `h = g^s`. Prefer `NewCommitmentKeyFromTranscript`, which derives `h` by hashing transcript output into the group and pairs it with the group's canonical generator. An externally supplied key is supported only when it comes from a trusted setup or other ceremony that guarantees the discrete-log relation between `g` and `h` is unknown.

`NewCommitmentKeyUnchecked` only rejects identity elements and identical generators. Use it only when the unknown-discrete-log precondition has already been established outside this package. CBOR-decoded keys have the same requirement and must not be accepted from an untrusted source as a binding CRS.

## Algorithms

- **Commit(message, prng)**: samples a fresh witness from the scalar field and returns `(commitment, witness)` where $commitment = g^{message} \cdot h^{witness}$.
- **CommitWithWitness(message, witness)**: deterministic commitment using caller-supplied randomness.
- **Verify(commitment, message, witness)**: recomputes $g^{message} \cdot h^{witness}$ and compares with the provided commitment.
- **ReRandomise(commitment, key, prng)**: blinds an existing commitment with fresh randomness, returning the updated commitment and witness.

## Homomorphism

Multiplying two commitments combines their messages and randomness additively. Scalar multiplication by a `Message` scales the committed value. These operations make the scheme suitable for simple aggregation or linear proof systems.
