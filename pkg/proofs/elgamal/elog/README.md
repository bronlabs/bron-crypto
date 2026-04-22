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

Rather than instantiating Figure 23 as a single Maurer homomorphism, this
package realizes $R_{\mathrm{elog}}$ as the AND-composition of two existing
Maurer protocols, glued by a consistency check on the witnesses:

1. **`elcomop`** ([../elcomop](../elcomop)) — proves knowledge of an opening
   $(M', \lambda) \in G \times \mathbb{F}_q$ of the ElGamal commitment
   $(L, M) = (g^\lambda,\; M' \cdot X^\lambda)$.
2. **`schnorr`** ([../../dlog/schnorr](../../dlog/schnorr)) instantiated with
   base $h$ — proves knowledge of $y \in \mathbb{F}_q$ such that $Y = h^y$.

The AND-composition runs both sub-protocols under the same verifier
challenge $e$. On its own this would only prove
"$\exists\, (M', \lambda, y)$ with $L = g^\lambda,\ M = M' X^\lambda,\ Y = h^y$";
`NewWitness` therefore enforces the binding

$$
M' = g^y
$$

on the composed witness before any transcript is produced. Substituting
$M' = g^y$ into the elcomop relation recovers $M = g^y X^\lambda$, exactly the
$R_{\mathrm{elog}}$ requirement.

### Transcript

Because elcomop's witness space is $G \times \mathbb{F}_q$ (not
$\mathbb{F}_q^2$), the transcript carries slightly more data than Figure 23:
the commitment and response both include an extra group element coming from
elcomop's plaintext component. Concretely, the first message is

$$
\bigl((g^\alpha,\; A' \cdot X^\alpha),\; h^m\bigr)\in(G\times G)\times G,
$$

with $A'\leftarrow G$ and $\alpha\leftarrow\mathbb{F}_q$ sampled by the
elcomop prover, $m\leftarrow\mathbb{F}_q$ by the Schnorr prover, and the
response is

$$
\bigl((A'\cdot(g^y)^e,\; \alpha + e\lambda),\; m + ey\bigr)\in(G\times\mathbb{F}_q)\times\mathbb{F}_q.
$$

Setting $A' = g^m$ reproduces Figure 23; with general $A'$ the transcript
verifies the same relation via the two sub-protocols' verifiers.

## Reference

Figure 23 of [CGGMP21](https://eprint.iacr.org/2021/060.pdf).
