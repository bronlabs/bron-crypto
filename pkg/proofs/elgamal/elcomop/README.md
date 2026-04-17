# Proof of knowledge of opening of ElGamal Commitment

This package implements a sigma protocol for proving knowledge of an opening of
an ElGamal commitment, using Maurer's generic group-homomorphism based
framework.

An ElGamal commitment to a message $M \in G$ with nonce $\lambda \in \mathbb{F}_q$
under public key $X \in G$ is the pair

$$
(\Gamma, \Delta) = (g^\lambda,\; M \cdot X^\lambda).
$$

The relation proved is

```math
R_{\mathrm{elcomop}} =
\left\{
\left( (G, g, X, \Gamma, \Delta),\; (M,\lambda) \right)
\;\middle|\;
\Gamma = g^\lambda,\;
\Delta = M \cdot X^\lambda
\right\}.
```

**Public input:** $(G, g, X, \Gamma, \Delta)$, where $G$ is a prime-order group
with generator $g$, $X \in G$ is the ElGamal public key, and $(\Gamma, \Delta)$
is the ElGamal commitment.

**Witness:** $(M, \lambda) \in G \times \mathbb{F}_q$ such that

$$
\Gamma = g^\lambda,\qquad \Delta = M \cdot X^\lambda.
$$

## Maurer interpretation

This protocol is a direct instance of Maurer's "proof of knowledge of a preimage
under a group homomorphism".

### Witness group

$$
G_w = G \times \mathbb{F}_q
$$

with componentwise group operation (multiplication in $G$, addition in
$\mathbb{F}_q$):

$$
(M,\lambda) \cdot (M',\lambda') = (M \cdot M',\; \lambda + \lambda').
$$

### Statement group

$$
H = G \times G
$$

with componentwise multiplication:

$$
(a,b) \cdot (a',b') = (a a',\; b b').
$$

### Homomorphism

$$
\varphi(M,\lambda) = \bigl(g^\lambda,\; M \cdot X^\lambda\bigr).
$$

The public statement is

$$
(\Gamma, \Delta) = \varphi(M,\lambda).
$$

### Sigma protocol in Maurer form

#### Protocol

1. Prover samples a random mask $k = (A, \alpha) \leftarrow G \times \mathbb{F}_q$
   and sends the first message

$$
t = \varphi(A, \alpha) = \bigl(g^\alpha,\; A \cdot X^\alpha\bigr).
$$

2. Verifier sends a challenge $e \in \mathbb{F}_q$.

3. Prover responds with

$$
r = k \cdot (M,\lambda)^e = \bigl(A \cdot M^e,\; \alpha + e\lambda\bigr).
$$

#### Verification

Accept iff

$$
\varphi(r) = t \cdot (\Gamma, \Delta)^e.
$$
