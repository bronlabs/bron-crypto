# Dlog with ElGamal Commitment

This package implements Figure23 of [CGGMP21](https://eprint.iacr.org/2021/060.pdf) titled Dlog with Elgamal Commitments. Specifically, It implements the sigma protocol for the following NP-Relation, using Maurer's generic group-homomorphism based framework.

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

## Figure 23 (\(\Pi^{\mathrm{elog}}\))

**Public input:** \((L, M, X, Y, g, h)\)

**Witness:** \((y,\lambda) \in \mathbb{F}_q^2\) such that
\[
L = g^\lambda,\qquad M = g^y X^\lambda,\qquad Y = h^y.
\]

### Protocol

1. Prover samples random \(\alpha, m \leftarrow \mathbb{F}_q\), and sends
   \[
   A = g^\alpha,\qquad N = g^m X^\alpha,\qquad B = h^m.
   \]

2. Verifier sends a challenge
   \[
   e \leftarrow \mathbb{F}_q.
   \]

3. Prover responds with
   \[
   z = \alpha + e\lambda,\qquad u = m + ey.
   \]

### Verification

Accept iff
\[
g^z = A L^e,
\]
\[
g^u X^z = N M^e,
\]
\[
h^u = B Y^e.
\]

## Maurer interpretation

This protocol is a direct instance of Maurer’s “proof of knowledge of a preimage under a group homomorphism”.

### Witness group

\[
G_w = \mathbb{F}_q^2
\]
with componentwise addition:
\[
(y,\lambda) + (y',\lambda') = (y+y',\lambda+\lambda').
\]

### Statement group

\[
H = G \times G \times G
\]
with componentwise multiplication:
\[
(a,b,c)\cdot(a',b',c') = (aa',bb',cc').
\]

### Homomorphism

\[
f(y,\lambda) = \bigl(g^\lambda,\; g^y X^\lambda,\; h^y\bigr).
\]

The public statement is
\[
(L,M,Y)=f(y,\lambda).
\]

### Sigma protocol in Maurer form

- random mask:
  \[
  k = (m,\alpha)
  \]

- first message:
  \[
  t = f(m,\alpha) = (A,N,B)
  \]

- challenge:
  \[
  e
  \]

- response:
  \[
  r = k + e\cdot (y,\lambda) = (u,z)
  \]

- verifier check:
  \[
  f(r) = t \cdot f(y,\lambda)^e
  \]

which expands to
\[
g^z = A L^e,\qquad
g^u X^z = N M^e,\qquad
h^u = B Y^e.
\]

## Reference

Figure 23 of [CGGMP21](https://eprint.iacr.org/2021/060.pdf)
