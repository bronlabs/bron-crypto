# Generalised ElGamal Cryptosystem

This package implements the Generalized ElGamal cryptosystem over any finite abelian cyclic group G, following section 8.4 of the Handbook of Applied Cryptography (Menezes, van Oorschot, Vanstone). Internally, we adapt the implementation to match ElGamal instantiation of GIFT.

## Overview

- Key pair: secret scalar `a`, public key `h = g^a` for a group generator `g`.
- Encryption of `m ∈ G` with nonce `r ∈ [1, n−1]`: `c = (γ, δ) = (g^r, m·h^r)`.
- Decryption with `a`: `m = δ · γ^{−a}`.
- Security: **IND-CPA under the Decisional Diffie–Hellman assumption** in `G`.
  Typical instantiations are prime-order elliptic-curve groups (k256, p256,
  ed25519 prime subgroup). The nonce must be fresh, secret, and non-zero — a
  zero nonce yields `(1, m)`, leaking the plaintext, and a reused nonce leaks the
  ratio of two plaintexts.
- The message space is the group `G` itself; encoding application data into group
  elements is the caller's responsibility.

## Types

- `PublicKey`: the element `h = g^a`; encrypts and runs the homomorphic operations.
- `SecretKey`: embeds `PublicKey` and holds the secret scalar `a`, the decryption
  trapdoor. `Public()` returns the public key with `a` stripped.
- `Plaintext`: a group element `m ∈ G`.
- `Nonce`: the encryption randomness `r ∈ Z/nZ \ {0}`.
- `Ciphertext`: the pair `(γ, δ) ∈ G²`, validated to be torsion-free (in the
  prime-order subgroup) to resist small-subgroup attacks.

## Homomorphism

ElGamal is multiplicatively homomorphic: `CiphertextOp` multiplies ciphertexts
component-wise, encrypting the product of the plaintexts (`PlaintextOp`) under the
sum of the nonces (`NonceOp`). `ReRandomise(c, r)` multiplies by `(g^r, h^r)` to
produce a fresh, unlinkable encryption of the same message, and `Shift(c, δ)`
multiplies by `(1, δ)` to turn an encryption of `m` into one of `m·δ` under the same
nonce. These operations are implemented through the GIFT framework as
`Representative(m) · IdentityNoise(r)`.

## Reference
<!-- paper: docs/papers/Handbook_of_Applied_Cryptography.pdf  -->
- Section 8.4 of [Handbook of Applied Cryptography, Chapter 8](https://cacr.uwaterloo.ca/hac/about/chap8.pdf) (Menezes, van Oorschot, Vanstone).
<!-- paper: docs/papers/2010-501_20120106_104554.pdf -->
- Section 5.1 of [2010/501](https://eprint.iacr.org/2010/501)
