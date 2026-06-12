# CGGMP21 Paillier Affine Operation with Group Commitment

This package implements the sigma protocol Pi aff-g from Appendix A.3, Figure 25 of CGGMP21.

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

The implementation exposes `ell` as `l`, `ell'` as `lPrime`, and the statistical slack as `epsilon`.

## Protocol

The prover samples:

$$
\alpha \leftarrow \pm 2^{\ell+\epsilon},\quad
\beta \leftarrow \pm 2^{\ell'+\epsilon},
$$

$$
r \leftarrow Z^*_{N_0},\quad r_Y \leftarrow Z^*_{N_1},
$$

$$
\gamma \leftarrow \pm 2^{\ell+\epsilon}\hat N,\quad
m \leftarrow \pm 2^\ell\hat N,
$$

$$
\delta \leftarrow \pm 2^{\ell'+\epsilon}\hat N,\quad
\mu \leftarrow \pm 2^{\ell'}\hat N.
$$

It sends:

$$
A = C^\alpha (1+N_0)^\beta r^{N_0} \bmod N_0^2,\quad
B_x = g^\alpha,\quad
B_y = (1+N_1)^\beta r_Y^{N_1} \bmod N_1^2,
$$

$$
E = s^\alpha t^\gamma,\quad
F = s^\beta t^\delta,\quad
S = s^x t^m,\quad
T = s^y t^\mu \pmod{\hat N}.
$$

For challenge `e`, the response is:

$$
z_1 = \alpha + ex,\quad
z_2 = \beta + ey,\quad
z_3 = \gamma + em,\quad
z_4 = \delta + e\mu,
$$

$$
w = r\rho^e \bmod N_0,\quad
w_Y = r_Y\rho_Y^e \bmod N_1.
$$

The verifier checks:

$$
C^{z_1}(1+N_0)^{z_2}w^{N_0} = AD^e \bmod N_0^2,
$$

$$
g^{z_1} = B_xX^e,
$$

$$
(1+N_1)^{z_2}w_Y^{N_1} = B_yY^e \bmod N_1^2,
$$

$$
s^{z_1}t^{z_3} = ES^e,\quad
s^{z_2}t^{z_4} = FT^e \pmod{\hat N},
$$

and the widened ranges:

$$
z_1 \in \pm 2^{\ell+\epsilon},\quad z_2 \in \pm 2^{\ell'+\epsilon}.
$$

## Implementation Notes

- `Statement` stores `N0`, `N1`, `C`, `D`, `Y`, and `X`.
- `Witness` stores `x` as `*num.Int`, `y` as a Paillier plaintext under `N1`, and the two Paillier nonces.
- Signed integer samples use byte-aligned two's-complement sampling over the requested bit length, so `±q` is interpreted as `[-q/2, q/2)`. A sample from `2^t * N` is implemented as a signed sample with bit length `t + bitlen(N)`.
- `ValidateStatement` checks that the witness opens `X`, `Y`, and `D`, and that `x` and `y` satisfy the configured narrow ranges.
- Statement validation checks that both Paillier moduli can encode the widened `z2` range `lPrime + epsilon` in their symmetric plaintext intervals.
- The challenge is interpreted as signed two's-complement big-endian bytes with computational-security length.

## Reference

<!-- paper: docs/papers/2021-060_20241021_172019.pdf [Appendix A.3, Figure 25] -->
- Canetti, Gennaro, Goldfeder, Makriyannis, Peled.
  [UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts](https://eprint.iacr.org/2021/060),
  Appendix A.3, Figure 25.
