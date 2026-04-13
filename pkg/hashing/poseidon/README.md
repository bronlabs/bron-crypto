# poseidon

Poseidon hash function over the Pallas base field, designed for efficient use in zero-knowledge proof systems.
The sponge absorbs field elements in rate-sized blocks, the last partial block must be zero-padded,
and callers who need injective variable-length hashing must perform their own framing, length encoding,
or domain separation before absorption.

Implements the sponge-based construction from [Poseidon: A New Hash Function for Zero-Knowledge Proof Systems](https://eprint.iacr.org/2019/458).
