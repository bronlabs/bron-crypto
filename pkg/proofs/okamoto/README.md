# Okamoto's Proof of Knowledge of a Representation

Consider a group $H$ of prime order $q$ and let $h_1, \ldots, h_m$ be generators of $H$. A **representation** of an element $z \in H$ with respect to these generators is a tuple $(x_1, \ldots, x_m) \in \mathbb{Z}_q^m$ such that

$$z = h_1^{x_1} \cdot h_2^{x_2} \cdots h_m^{x_m}.$$

This package implements a sigma protocol proving knowledge of such a representation, instantiated via Maurer's unifying framework [1].

## Protocol

The one-way homomorphism is multi-exponentiation:

$$\varphi(x_1, \ldots, x_m) = \prod_{i=1}^{m} h_i^{x_i}.$$

Given a statement $z$ and witness $(x_1, \ldots, x_m)$:

- **Commitment**: the prover samples $s_1, \ldots, s_m \stackrel{\$}{\leftarrow} \mathbb{Z}_q$ and sends $a = \prod h_i^{s_i}$.
- **Challenge**: the verifier sends a random $e$.
- **Response**: the prover sends $z_i = s_i + e \cdot x_i$ for each $i$.
- **Verification**: check that $\prod h_i^{z_i} = a \cdot z^e$.

The protocol has special soundness (knowledge-extraction from two accepting transcripts with distinct challenges) and is honest-verifier zero-knowledge (the simulator samples a random response and derives a consistent commitment).

## Pedersen Commitment Opening

When $m = 2$ with generators $(g, h)$, a Pedersen commitment $C = g^m \cdot h^r$ is exactly a representation of $C$. The Okamoto protocol therefore proves knowledge of the opening $(m, r)$ without revealing either value.

## References

- [1] Maurer, U. [Unifying Zero-Knowledge Proofs of Knowledge](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf). AFRICACRYPT 2009.
- [2] Okamoto, T. [Provably Secure and Practical Identification Schemes and Corresponding Signature Schemes](https://link.springer.com/chapter/10.1007/3-540-48071-4_3). CRYPTO 1992.
