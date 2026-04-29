# Maurer09 Sigma Protocol

Generic sigma protocol implementation based on Maurer's unifying framework for zero-knowledge proofs of knowledge [1].

## Background

The framework captures a wide class of sigma protocols via a single abstraction: a **one-way group homomorphism** $\varphi \colon G \to H$ between a pre-image group $G$ and an image group $H$. Given a statement $x \in H$, the prover demonstrates knowledge of a witness $w \in G$ such that $\varphi(w) = x$.

## Protocol

The three-move sigma protocol proceeds as follows:

1. **Commitment.** The prover samples $s \stackrel{R}{\leftarrow} G$ and sends $a = \varphi(s)$.
2. **Challenge.** The verifier sends a random challenge $e$.
3. **Response.** The prover sends $z = s \cdot w^e$ (in the pre-image group).
4. **Verification.** The verifier accepts iff $\varphi(z) = a \cdot x^e$.

The protocol has 2-special soundness: given two accepting transcripts $(a, e_1, z_1)$ and $(a, e_2, z_2)$ with $e_1 \neq e_2$, a witness can be extracted.

## Anchor

Extraction requires computing the pre-image of $x^L$ for a public scalar $L$ (the `Anchor` interface). This generalises extraction to groups where direct inversion of the challenge difference may not be straightforward (e.g., groups of unknown order such as RSA groups).

## Instantiations

This package is internal. Concrete protocols that build on it:

| Protocol | Homomorphism | Package |
|---|---|---|
| Schnorr (DLOG) | $\varphi(w) = g^w$ | `proofs/dlog/schnorr` |
| Okamoto (representation) | $\varphi(w_1, \ldots, w_m) = \prod h_i^{w_i}$ | `proofs/okamoto` |
| Paillier nth-root | $\varphi(w) = w^N \bmod N^2$ | `proofs/paillier/nthroot` |

## API

```go
protocol, err := maurer09.NewProtocol(
    challengeByteLen,
    soundnessError,
    name,
    imageGroup,
    preImageGroup,
    oneWayHomomorphism,
    anchor,
    prng,
    // optional: WithImageScalarMul(...), WithPreImageScalarMul(...)
)
```

The scalar multiplication in either group can be overridden via `WithImageScalarMul` and `WithPreImageScalarMul` options (used, e.g., by the Paillier nth-root protocol where exponentiation differs from the default).

## References

<!-- paper[Maurer09]: docs/papers/Maurer09.pdf -->
- [1] Maurer, U. [Unifying Zero-Knowledge Proofs of Knowledge](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf). AFRICACRYPT 2009.
