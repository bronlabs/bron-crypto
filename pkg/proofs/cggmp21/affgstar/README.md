# CGGMP21 Setup-Less Paillier Affine Operation with Group Commitment

This package implements the sigma protocol Pi aff-g* from Appendix A.5, Figure 27 of CGGMP21.

The statement is `(G, g, N0, N1, C, D, Y, X)`. The witness is `(x, y, rho, rhoY)` such that:

$$
x \in \pm 2^\ell,\quad y \in \pm 2^{\ell'},\quad X = g^x,
$$

$$
Y = (1+N_1)^y \rho_Y^{N_1} \bmod N_1^2,
$$

and

$$
D = C^x (1+N_0)^y \rho^{N_0} \bmod N_0^2.
$$

The implementation exposes `ell` as `l`, `ell'` as `lPrime`, and the statistical slack as `epsilon`. It fixes the protocol repetition count to `kappa = base.ComputationalSecurityBits`.

## Protocol

For each `j` in `[kappa]`, the prover samples:

$$
\alpha_j \leftarrow \pm 2^{\ell+\epsilon},\quad
\beta_j \leftarrow \pm 2^{\ell'+\epsilon},
$$

$$
r_j \leftarrow Z^*_{N_0},\quad s_j \leftarrow Z^*_{N_1}.
$$

It sends:

$$
A_j = C^{\alpha_j}(1+N_0)^{\beta_j}r_j^{N_0} \bmod N_0^2,
$$

$$
R_j = g^{\alpha_j},
$$

$$
B_j = (1+N_1)^{\beta_j}s_j^{N_1} \bmod N_1^2.
$$

The verifier replies with challenge bits `e_j in {0,1}`. The response is:

$$
z_j = \alpha_j + e_jx,\quad z'_j = \beta_j + e_jy,
$$

$$
w_j = r_j\rho^{e_j} \bmod N_0,\quad
\lambda_j = s_j\rho_Y^{e_j} \bmod N_1.
$$

The verifier checks, for every `j`:

$$
C^{z_j}(1+N_0)^{z'_j}w_j^{N_0} = A_jD^{e_j} \bmod N_0^2,
$$

$$
g^{z_j} = R_jX^{e_j},
$$

$$
(1+N_1)^{z'_j}\lambda_j^{N_1} = B_jY^{e_j} \bmod N_1^2,
$$

and the widened ranges:

$$
z_j \in \pm 2^{\ell+\epsilon},\quad z'_j \in \pm 2^{\ell'+\epsilon}.
$$

## Implementation Notes

- `Statement` stores `N0`, `N1`, `C`, `D`, `Y`, and `X`.
- `Witness` stores `x` as `*num.Int`, `y` as a Paillier plaintext under `N1`, and the two Paillier nonces.
- The challenge is `base.ComputationalSecurityBytesCeil` bytes interpreted as `base.ComputationalSecurityBits` challenge bits. This intentionally fixes the repetition count to 128 bits rather than exposing `kappa` as a separate protocol parameter.
- Signed integer samples use byte-aligned two's-complement sampling over exactly the requested byte length.
- The repeated Paillier encryptions use `encryption.EncryptManyWithNonces`.
- `ValidateStatement` checks that the witness opens `X`, `Y`, and `D`, and that `x` and `y` satisfy the configured narrow ranges.
- Statement validation checks that both Paillier moduli can encode the widened `zPrime` range `lPrime + epsilon` in their symmetric plaintext intervals.

## Reference

<!-- paper: docs/papers/2021-060_20241021_172019.pdf [Appendix A.5, Figure 27] -->
- Canetti, Gennaro, Goldfeder, Makriyannis, Peled.
  [UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts](https://eprint.iacr.org/2021/060),
  Appendix A.5, Figure 27.
