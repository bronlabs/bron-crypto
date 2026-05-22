# CGGMP21 Small-Factor Proof

This package implements the sigma protocol $\Pi^{\mathsf{fac}}$ from Figure 26 of CGGMP21.

The protocol is constructed with auxiliary Pedersen parameters $(\hat N, s, t)$ represented as an `intcom.CommitmentKey`. The statement is a Paillier public key $N_0$, and the witness is the matching Paillier secret key containing the factorisation $(p,q)$ such that $N_0=pq$.

## Protocol

Let $\ell$ be the range parameter and $\epsilon$ the statistical slack. The prover samples

$$
\alpha,\beta \leftarrow \pm 2^{\ell+\epsilon}\sqrt{N_0},\quad
\mu,\nu \leftarrow \pm 2^\ell \hat N,\quad
r \leftarrow \pm 2^{\ell+\epsilon}N_0\hat N,\quad
x,y \leftarrow \pm 2^{\ell+\epsilon}\hat N.
$$

Let $\mathsf{Com}(m;r)=s^m t^r \bmod \hat N$ be the Ring-Pedersen commitment implemented by `intcom.CommitmentKey`. The prover sends

$$
P=\mathsf{Com}(p;\mu),\quad
Q=\mathsf{Com}(q;\nu),\quad
A=\mathsf{Com}(\alpha;x),\quad
B=\mathsf{Com}(\beta;y),\quad
T=Q^\alpha\cdot\mathsf{Com}(0;r)
\pmod{\hat N}.
$$

The Fiat-Shamir challenge bytes are interpreted as an $\ell$-bit signed two's-complement integer, so $e \in [-2^{\ell-1},2^{\ell-1})$. The prover responds with

$$
z_1=\alpha+ep,\quad
z_2=\beta+eq,\quad
w_1=x+e\mu,\quad
w_2=y+e\nu,\quad
v=r-e\nu p.
$$

The verifier sets $R=\mathsf{Com}(N_0;0)$ and checks

$$
\mathsf{Open}(AP^e,z_1,w_1),\quad
\mathsf{Open}(BQ^e,z_2,w_2),\quad
\mathsf{Open}(TR^eQ^{-z_1},0,v)
\pmod{\hat N},
$$

which is equivalent to the Figure 26 equations
$s^{z_1}t^{w_1}=AP^e$,
$s^{z_2}t^{w_2}=BQ^e$, and
$Q^{z_1}t^v=TR^e$. It also verifies the Figure 26 range checks for $z_1,z_2$.

## Implementation Notes

- `NewProtocol` takes the auxiliary `*intcom.CommitmentKey`; the Fiat-Shamir domain includes a digest of this key.
- `Statement` stores the public `*paillier.PublicKey`.
- `Witness` stores the matching `*paillier.SecretKey`; the factorisation is read from the secret key when needed.
- Prover commitments are computed with `CommitmentKey.CommitWithWitness`, `CommitmentKey.CommitmentScalarOp`, and `CommitmentKey.CommitmentOp`; verification uses `CommitmentKey.Open` for the three acceptance equations above.
- Range sampling assumes byte-aligned parameters. Internally, signed masks are sampled by drawing `bitLen/8` random bytes, prepending a random sign byte (`0x00` or `0xff`), and decoding the result as two's-complement big-endian. This samples uniformly from $[-2^{\mathsf{bitLen}},2^{\mathsf{bitLen}})$ up to the intentionally excluded signed-bound endpoint in the $z_1,z_2$ verifier checks.
- The implementation uses true modulus bit lengths for range sizing and requires the public Paillier modulus and auxiliary commitment modulus to be byte-aligned.
- `paillier.SecretKey` carries equal-bit-length Paillier factors. After checking $N_0=pq$, this balanced factor shape satisfies Figure 26's $p,q \in \pm\sqrt{N_0}\cdot 2^\ell$ witness bound.
- The Fiat-Shamir challenge bytes are interpreted directly as two's-complement big-endian; for byte-aligned $\ell$, the challenge length is exactly $\ell/8$ bytes.

## Reference

- Canetti, Gennaro, Goldfeder, Makriyannis, Peled. [UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts](https://eprint.iacr.org/2021/060), Appendix A.4, Figure 26.
