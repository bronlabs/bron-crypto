# Pedersen Commitments

Pedersen commitments are perfectly hiding and computationally binding (under the discrete logarithm assumption) over a prime-order group. This package implements a two-generator instantiation with additive homomorphism and re-randomisation support.

## Overview

- Common reference string: two independent generators `g` and `h` of the same prime-order group.
- Commitment to scalar message $m$ with randomness $r$: $C = g^m \cdot h^r$.
- Additive homomorphism: multiplying commitments corresponds to adding messages; commitments can be re-randomised without changing the message.
- All types implement CBOR encoding for transport and persistence.

## Types

- `Key`: holds generators `g` and `h`; constructor rejects identity elements and identical generators.
- `Message`: wraps the scalar message in the group’s field.
- `Witness`: randomness used to hide the message.
- `Commitment`: prime-group element representing $g^m \cdot h^r$.
- `Scheme`: wires the committer and verifier around a fixed `Key`.

## Algorithms

- **Commit(message, prng)**: samples a fresh witness from the scalar field and returns `(commitment, witness)` where $commitment = g^{message} \cdot h^{witness}$.
- **CommitWithWitness(message, witness)**: deterministic commitment using caller-supplied randomness.
- **Verify(commitment, message, witness)**: recomputes $g^{message} \cdot h^{witness}$ and compares with the provided commitment.
- **ReRandomise(commitment, key, prng)**: blinds an existing commitment with fresh randomness, returning the updated commitment and witness.

## Homomorphism

Multiplying two commitments combines their messages and randomness additively. Scalar multiplication by a `Message` scales the committed value. These operations make the scheme suitable for simple aggregation or linear proof systems.
