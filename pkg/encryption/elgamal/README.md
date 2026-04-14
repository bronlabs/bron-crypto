# Generalized ElGamal Cryptosystem

This package implements the Generalized ElGamal cryptosystem over any finite abelian cyclic group G, following section 8.4 of the *Handbook of Applied Cryptography* (Menezes, van Oorschot, Vanstone).

## Mathematical Foundation

Security relies on the Decisional Diffie-Hellman (DDH) assumption in G. Typical instantiations use prime-order elliptic curve groups (secp256k1, P-256, Ed25519 prime subgroup).

### Key Structure

- **Private key**: scalar `a` sampled uniformly from `Z/nZ \ {0}`
- **Public key**: group element `h = g^a`
- **Plaintext space**: elements of `G`
- **Ciphertext space**: pairs `(c1, c2) in G x G`

### Encryption

For plaintext `m in G` and random nonce `r in Z/nZ \ {0}`:

```
Enc(m, r) = (g^r,  m * h^r)
```

### Decryption

```
Dec(c1, c2) = c2 * (c1^a)^{-1} = m
```

### Homomorphic Properties

The scheme is group-homomorphic over G:

| Operation | Ciphertext Computation | Plaintext Effect |
|-----------|------------------------|------------------|
| `Op(c, c')` | `(c1 * c1', c2 * c2')` | `m * m'` |
| `ScalarOp(c, k)` | `(c1^k, c2^k)` | `m^k` |
| `Shift(c, m')` | `(c1, c2 * m')` | `m * m'` |
| `ReRandomise(c, r')` | `(c1 * g^r', c2 * h^r')` | `m` (unchanged) |

**Note**: `Shift` modifies only `c2` and does not re-randomise the ciphertext; an observer who sees both the original and shifted ciphertexts can detect the relationship. Use `ReRandomise` afterwards if unlinkability is needed.

## Usage

### Key Generation

```go
curve := k256.NewCurve()
scheme, _ := elgamal.NewScheme(curve)
kg, _ := scheme.Keygen()
sk, pk, _ := kg.Generate(rand.Reader)
```

### Encryption and Decryption

```go
enc, _ := scheme.Encrypter()
dec, _ := scheme.Decrypter(sk)

pt, _ := elgamal.NewPlaintext(someGroupElement)
ct, nonce, _ := enc.Encrypt(pt, pk, rand.Reader)
recovered, _ := dec.Decrypt(ct)
```

### Homomorphic Addition

```go
ct1, _, _ := enc.Encrypt(pt1, pk, rand.Reader)
ct2, _, _ := enc.Encrypt(pt2, pk, rand.Reader)

ctProduct := ct1.Op(ct2)           // encrypts pt1 * pt2
ctScaled := ct1.ScalarOp(scalar)   // encrypts pt1^scalar
```

### Re-randomisation

```go
ctNew, _, _ := ct.ReRandomise(pk, rand.Reader)  // same plaintext, unlinkable ciphertext
```

## Security Notes

- **IND-CPA** under DDH. The scheme is probabilistic: encrypting the same message twice produces different ciphertexts.
- **Not IND-CCA2**: ciphertexts are malleable by design (the homomorphic operations exploit this). Protocols requiring ciphertext integrity must add authentication (e.g. Cramer-Shoup, or a ZK proof of well-formedness).
- **Nonce reuse** under the same key leaks the plaintext ratio `m1 * m2^{-1}`. Never reuse nonces; use `Encrypt` (which samples fresh randomness) rather than `EncryptWithNonce` unless your protocol requires determinism.
- **Subgroup validation**: constructors reject identity elements and torsion points to prevent small-subgroup attacks on curves with cofactor > 1.

## Reference

- Section 8.4 of [Handbook of Applied Cryptography, Chapter 8](https://cacr.uwaterloo.ca/hac/about/chap8.pdf) (Menezes, van Oorschot, Vanstone).
