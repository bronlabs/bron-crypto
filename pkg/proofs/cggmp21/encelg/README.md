# CGGMP21 Range Proof with ElGamal Commitment

This package implements the sigma protocol Pi enc-elg from Appendix A.2, Figure 24 of CGGMP21.

The statement is `(G, g, N0, C, A, (B, X))`. The witness is `(x, rho, a, b)` such that:

$$
x \in \pm 2^\ell,\quad C = (1+N_0)^x\rho^{N_0} \bmod N_0^2,
$$

and

$$
A = g^a,\quad (B, X) = (g^b, A^b g^x).
$$

The implementation exposes `ell` as `l` and the statistical slack as `epsilon`.

## Protocol

The prover samples:

$$
\alpha \leftarrow \pm 2^{\ell+\epsilon},\quad
\beta \leftarrow F_q,\quad
\mu \leftarrow \pm 2^\ell \hat N,
$$

$$
r \leftarrow Z^*_{N_0},\quad
\gamma \leftarrow \pm 2^{\ell+\epsilon}\hat N.
$$

It sends:

$$
S = s^x t^\mu,\quad T = s^\alpha t^\gamma,
$$

$$
D = (1+N_0)^\alpha r^{N_0} \bmod N_0^2,
$$

$$
(Z, Y) = (g^\beta, A^\beta g^\alpha).
$$

The verifier replies with a signed 16-byte challenge `e`. The response is:

$$
z_1 = \alpha + ex,\quad z_2 = r\rho^e \bmod N_0,
$$

$$
z_3 = \gamma + e\mu,\quad w = \beta + eb \bmod q.
$$

The verifier checks:

$$
(1+N_0)^{z_1}z_2^{N_0} = DC^e \bmod N_0^2,
$$

$$
\operatorname{Enc}_A(g^{z_1}; w) = (Z, Y)(B, X)^e,
$$

$$
s^{z_1}t^{z_3} = TS^e \bmod \hat N,
$$

and the widened range:

$$
z_1 \in \pm 2^{\ell+\epsilon}.
$$

## Implementation Notes

- `Statement` stores `N0`, `C`, `A` as an ElGamal public key, and `(B, X)` as an ElGamal ciphertext named `bx`.
- `Witness` stores `x` as `*num.Int`, `rho` as a Paillier nonce, `a` as an ElGamal secret key, and the `(B, X)` nonce as `bx`.
- `Commitment` stores `(Z, Y)` as an ElGamal ciphertext named `yz` under `A`.
- The challenge is interpreted as a signed integer from exactly `base.ComputationalSecurityBytesCeil` bytes.
- Signed integer samples use byte-aligned two's-complement sampling over exactly the requested byte length.
- `ValidateStatement` checks that the witness opens `C`, `A`, and the ElGamal ciphertext `(B, X)`, and that `x` satisfies the configured narrow range.
- Statement validation checks that the Paillier modulus can encode the widened `z1` range `l + epsilon` in its symmetric plaintext interval.

## Reference

<!-- paper: docs/papers/2021-060_20241021_172019.pdf [Appendix A.2, Figure 24] -->
- Canetti, Gennaro, Goldfeder, Makriyannis, Peled.
  [UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts](https://eprint.iacr.org/2021/060),
  Appendix A.2, Figure 24.
