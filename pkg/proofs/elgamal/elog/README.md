# Dlog with ElGamal Commitment

This package implements Figure 23 of [CGGMP21](https://eprint.iacr.org/2021/060.pdf),
titled Dlog with Elgamal Commitments. It is a sigma protocol for the following
NP-relation:

```math
R_{\mathrm{elog}} =
\left\{
\left( (G, g, L, M, X, Y, h), (y,\lambda) \right)
\;\middle|\;
L = g^\lambda,\;
M = g^y X^\lambda,\;
Y = h^y
\right\}.
```

## Figure 23 ($\Pi^{\mathrm{elog}}$)

**Public input:** $(L, M, X, Y, g, h)$

**Witness:** $(y,\lambda) \in \mathbb{F}_q^2$ such that

$$
L = g^\lambda,\qquad M = g^y X^\lambda,\qquad Y = h^y.
$$

### Protocol

1. Prover samples random $\alpha, m \leftarrow \mathbb{F}_q$, and sends

$$
A = g^\alpha,\qquad N = g^m X^\alpha,\qquad B = h^m.
$$

2. Verifier sends a challenge

$$
e \leftarrow \mathbb{F}_q.
$$

3. Prover responds with

$$
z = \alpha + e\lambda,\qquad u = m + ey.
$$

### Verification

Accept iff

$$
g^z = A L^e,\qquad
g^u X^z = N M^e,\qquad
h^u = B Y^e.
$$

## Implementation

This package instantiates Figure 23 directly as a single Maurer
homomorphism (`maurer09`), with the witness and statement spaces built from
the direct-power constructions in `pkg/base/algebra/constructions`.

### Witness group

$$
G_w = \mathbb{F}_q \times \mathbb{F}_q
$$

with componentwise addition. The witness is $(y, \lambda)$.

### Statement group

$$
H = G \times G \times G
$$

with componentwise multiplication. The statement is $(L, M, Y)$.

### Homomorphism

$$
\varphi(y, \lambda) = \bigl(g^\lambda,\; g^y X^\lambda,\; h^y\bigr).
$$

The first two components are computed with the same IND-CPA commitment key
that produced $(L, M)$, so the proof is bound to the committer's encoding;
the third is $h^y$.

### Sigma protocol in Maurer form

1. Prover samples a mask $(m, \alpha) \leftarrow \mathbb{F}_q^2$ and sends

$$
t = \varphi(m, \alpha) = \bigl(g^\alpha,\; g^m X^\alpha,\; h^m\bigr) = (A, N, B).
$$

2. Verifier sends a challenge $e$.

3. Prover responds with

$$
r = (m, \alpha) + e\,(y, \lambda) = \bigl(m + ey,\; \alpha + e\lambda\bigr) = (u, z).
$$

Verification checks $\varphi(r) = t \cdot (L, M, Y)^e$ componentwise, which is
exactly the three equations of Figure 23:

$$
g^z = A L^e,\qquad g^u X^z = N M^e,\qquad h^u = B Y^e.
$$

### Why a single homomorphism

An earlier revision realised $R_{\mathrm{elog}}$ as the AND-composition of
`elcomop` (opening $(M', \lambda)$ of $(L, M)$) and Schnorr ($Y = h^y$), and
enforced $M' = g^y$ only inside the prover's witness constructor. A verifier
cannot observe that constructor, so the composed proof only established
$\exists\,(M', \lambda, y)$ with $L = g^\lambda,\ M = M' X^\lambda,\ Y = h^y$,
letting a dishonest prover open $(L, M)$ to a value unrelated to $Y$.
Expressing the relation as one homomorphism over the shared witness
$(y, \lambda)$ makes $M = g^y X^\lambda$ part of what the verifier checks.

## Reference

<!-- paper: docs/papers/2021-060_20241021_172019.pdf [Appendix A.1, Figure 23] -->
Figure 23 of [CGGMP21](https://eprint.iacr.org/2021/060.pdf).
