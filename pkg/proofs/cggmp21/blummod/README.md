# Paillier-Blum Modulus Proof

Sigma protocol for proving that a public Paillier modulus $N$ is a Paillier-Blum modulus. The prover owns the factorisation $N = pq$, where $p$ and $q$ are primes satisfying $p, q \equiv 3 \pmod 4$, and $\gcd(N, \varphi(N)) = 1$.

## Input

The common input is the Paillier modulus $N$. In code, $N$ is carried by the sigma statement as a `*paillier.PublicKey`:

* provers and verifiers instantiate the protocol with fixed amplification parameter $m = 129$,
* provers and verifiers pass the Paillier public key in `Statement`,
* provers pass `*paillier.SecretKey` in the witness.

The prover validates that the witness secret key has the same modulus as the statement public key. It does not reject non-Blum trapdoors before proving; such a witness is allowed to attempt the protocol and fail while computing the response. $N$ is bound through `Statement.Bytes()` and therefore through the Fiat-Shamir transcript.

## Protocol

This implements CGGMP21 Figure 12 with $m = 129$. The prover samples $w \in \mathbb{Z}_N^*$ with Jacobi symbol $\operatorname{Jacobi}(w, N) = -1$. The verifier challenge is represented as a 32-byte seed; HKDF-SHA3-256 expands it to 129 32-byte blocks, and each block is hashed to an element $y_i \in \mathbb{Z}_N^*$. This adapts the paper's group-element challenge to the repository's byte-oriented sigma interface.

For each $y_i$, the prover sends $(x_i, a_i, b_i, z_i)$ such that:

* $z_i^N \equiv y_i \pmod N$,
* $x_i^4 \equiv (-1)^{a_i} w^{b_i} y_i \pmod N$,
* $a_i, b_i \in \{0, 1\}$.

The verifier also checks that $N$ is odd composite, $w \in \mathbb{Z}_N^*$, and $\operatorname{Jacobi}(w, N) = -1$.

## Security

For an invalid statement, CGGMP21 bounds the accepting probability by $2^{-m+1}$ when the verifier samples the $y_i$ independently. This implementation fixes $m = 129$ and derives the $y_i$ from a 32-byte seed using HKDF and `Group.Hash`, so the same 128-bit bound is interpreted in the random-oracle/PRF model used by Fiat-Shamir.

The paper gives an honest-verifier simulator that samples `w` and the challenge elements together. This repository's `sigma.Protocol.RunSimulator` API receives fixed challenge bytes, and simulating for an arbitrary fixed challenge would require the factorisation. For that reason `RunSimulator` returns an explicit unsupported error.

## Reference

<!-- paper: docs/papers/2021-060_20241021_172019.pdf [section 5.2 and figure 12] -->
* [CGGMP21, Section 5.2 and Figure 12](https://eprint.iacr.org/2021/060.pdf)
