# Realization of DKLs24 RVOLE functionality

This package implements RVOLE, the two-party OT-based multiplication protocol that is used inside [DKLs24](https://eprint.iacr.org/2023/765.pdf).
A two-party multiplication protocol between Alice and Bob is a protocol resulting in additive shares of the multiplication of Alice and Bob's secrets. In other words, Let $a$ be Alice's secret and $b$ be Bob's secret. The protocol outputs $c$ to Alice and $d$ to Bob such that $a * b = c + d$

The protocol we've implemented is batched for a batch size of `𝓁=2` ie. $a_i * b = c_i + d_i \;\forall i \in [\ell]$

Trivially, by providing random values as `a` and/or `b`, this protocol becomes a randomized multiplication protocol.

The details of the protocol are sketched in Protocol 5.2 of [DKLs24](https://eprint.iacr.org/2023/765.pdf).

## Best-effort Constant Time implementation

The code of this package is written in a best-effort mode to be Constant Time by: 
1. Removing data-dependent branching (e.g. if-else statements) and data-dependent iteration (e.g. data-dependent length of for-loops)
2. Using constant-time operations from primitives (e.g. constant-time field operations from `saferith`)
3. Delaying error/abort raising when tied to data (e.g., for loops in consistency checks) to avoid leaking unnecessary stop information. Note that this does not cover "static" errors (e.g., wrong size for hashing).
4. Using `crypto/subtle` functions whenever applicable.
