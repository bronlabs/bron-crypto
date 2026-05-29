# Paillier Cryptosystem

We implement Scheme 1 of [Paillier99](https://link.springer.com/chapter/10.1007/3-540-48910-X_16), in the [GIFT](https://eprint.iacr.org/2010/501) framework, using various optimizations from the literature.

## Overview

- Modulus `N = p·q`. The public key is `N`; the secret key is the factorisation.
- Encryption of `m ∈ Z_N` with nonce `r ∈ Z*_N`: `c = (1+N)^m · r^N mod N²`, an
  element of `Z*_{N²}`.
- Decryption recovers `m` from the factorisation via a CRT / Fermat-quotient
  computation. `Open` additionally recovers the nonce `r`.
- Security: **IND-CPA under the Decisional Composite Residuosity assumption**. The
  nonce must be fresh and secret; the public key trusts that `N` is a well-formed
  product of two large primes (when `N` is supplied by an untrusted party this must
  be proven separately, e.g. a Paillier-Blum modulus proof).

## Types

- `PublicKey`: the modulus `N` (as the group `Z*_{N²}`); encrypts and runs the
  homomorphism, cannot decrypt.
- `SecretKey`: embeds `PublicKey` and holds the factorisation plus precomputed CRT
  constants — the decryption trapdoor. `Public()` strips it. `Decrypt` recovers the
  plaintext and `Open` recovers plaintext **and** nonce (making encryption-based
  commitments extractable).
- `Plaintext`: a residue in `Z_N` (constructors for `Z_N`, `[0, N)`, and the signed
  symmetric range `[−N/2, N/2)`).
- `Nonce`: the secret randomness `r ∈ Z*_N`.
- `Ciphertext`: an element of `Z*_{N²}`.

Key generation comes in three flavours: `SampleSecretKey` (general primes),
`SampleBlumSecretKey` (Blum primes, `p ≡ q ≡ 3 mod 4`), and `SampleSafeSecretKey`
(safe primes) for protocols whose proofs require those forms.

## Homomorphism

Paillier is additively homomorphic: `CiphertextOp` multiplies ciphertexts,
encrypting the **sum** of the plaintexts (`PlaintextOp`) under the product of the
nonces (`NonceOp`); `CiphertextScalarOp` raises a ciphertext to a scalar, encrypting
the scaled plaintext. `ReRandomise(c, r)` multiplies by `r^N` to produce a fresh,
unlinkable encryption of the same message, and `Shift(c, δ)` multiplies by
`(1+N)^δ` to turn an encryption of `m` into one of `m+δ` under the same nonce. These
are implemented through the GIFT framework as `Representative(m) · IdentityNoise(r)`.

## References

<!-- paper: docs/papers/paillier99.pdf -->
- [Paillier, P. (1999). Public-Key Cryptosystems Based on Composite Degree Residuosity Classes.](https://link.springer.com/chapter/10.1007/3-540-48910-X_16)
<!-- paper: 2015-864_20150908_060334.pdf -->
- [Jost et al. Encryption Performance Improvements of the Paillier Cryptosystem](https://eprint.iacr.org/2015/864)
<!-- paper: docs/papers/2010-501_20120106_104554.pdf -->
- Section 5.2 of [2010/501](https://eprint.iacr.org/2010/501)
