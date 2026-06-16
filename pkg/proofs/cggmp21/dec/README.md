# CGGMP21 Paillier Special Decryption in the Exponent

This package implements the sigma protocol Pi dec from Appendix A.6, Figure 28 of CGGMP21.

The statement is `(G, g, N0, K, X, D, S)`. The witness is `(x, y, rho)` such that:

$$
x \in \pm 2^\ell,\quad y \in \pm 2^{\ell'},\quad X = g^x,\quad S = g^y,
$$

and

$$
(1+N_0)^y \rho^{N_0} = K^x D \bmod N_0^2.
$$

The implementation exposes `ell` as `l`, `ell'` as `lPrime`, and the statistical slack as `epsilon`. It fixes the protocol repetition count to `kappa = base.ComputationalSecurityBits`.

## Protocol

For each `j` in `[kappa]`, the prover samples:

$$
\alpha_j \leftarrow \pm 2^{\ell+\epsilon},\quad
\beta_j \leftarrow \pm 2^{\ell'+\epsilon},\quad
r_j \leftarrow Z^*_{N_0}.
$$

It sends:

$$
A_j = K^{-\alpha_j}(1+N_0)^{\beta_j}r_j^{N_0} \bmod N_0^2,
$$

$$
B_j = g^{\beta_j},\quad C_j = g^{\alpha_j}.
$$

The verifier replies with challenge bits `e_j in {0,1}`. The response is:

$$
z_j = \alpha_j + e_jx,\quad w_j = \beta_j + e_jy,
$$

$$
\nu_j = r_j\rho^{e_j} \bmod N_0.
$$

The verifier checks, for every `j`:

$$
(1+N_0)^{w_j}\nu_j^{N_0}K^{-z_j} = A_jD^{e_j} \bmod N_0^2,
$$

$$
g^{z_j} = C_jX^{e_j},\quad g^{w_j} = B_jS^{e_j},
$$

and the widened ranges:

$$
z_j \in \pm 2^{\ell+\epsilon},\quad w_j \in \pm 2^{\ell'+\epsilon}.
$$

## Implementation Notes

- `Statement` stores `N0`, `K`, `X`, `D`, and `S`.
- `Witness` stores `x` and `y` as `*num.Int`, and the Paillier nonce `rho`.
- The challenge is `base.ComputationalSecurityBytesCeil` bytes interpreted as `base.ComputationalSecurityBits` challenge bits. This intentionally fixes the repetition count to 128 bits rather than exposing `kappa` as a separate protocol parameter.
- Signed integer samples use byte-aligned two's-complement sampling over exactly the requested byte length.
- The repeated Paillier encryptions use `encryption.EncryptManyWithNonces`.
- `ValidateStatement` checks that the witness opens `X`, `S`, and the Paillier relation, and that `x` and `y` satisfy the configured narrow ranges.
- Statement validation checks that the Paillier modulus can encode the widened `w` range `lPrime + epsilon` in its symmetric plaintext interval.

## Reference

<!-- paper: docs/papers/2021-060_20241021_172019.pdf [Appendix A.6, Figure 28] -->
- Canetti, Gennaro, Goldfeder, Makriyannis, Peled.
  [UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts](https://eprint.iacr.org/2021/060),
  Appendix A.6, Figure 28.
