# Paillier Cryptosystem

This package implements the Paillier cryptosystem, an additive homomorphic public-key encryption scheme that enables computation on encrypted data.

## Mathematical Foundation

The Paillier cryptosystem operates over the group `(Z/n²Z)*` where `n = p · q` is an RSA modulus. Security relies on the Decisional Composite Residuosity Assumption (DCRA).

### Key Structure

- **Public key**: modulus `n` and generator `g = 1 + n`
- **Private key**: prime factors `p, q` (enables CRT-based decryption)
- **Plaintext space**: integers in `[-n/2, n/2)` (centred representation)
- **Ciphertext space**: elements of `(Z/n²Z)*`

### Encryption

For plaintext `m` and random nonce `r ∈ (Z/nZ)*`:

```
Enc(m, r) = g^m · r^n mod n²
         = (1 + m·n) · r^n mod n²
```

### Homomorphic Properties

The scheme supports three homomorphic operations:

| Operation | Ciphertext Computation | Plaintext Effect |
|-----------|------------------------|------------------|
| `HomAdd(c₁, c₂)` | `c₁ · c₂ mod n²` | `m₁ + m₂` |
| `HomSub(c₁, c₂)` | `c₁ · c₂⁻¹ mod n²` | `m₁ - m₂` |
| `ScalarMul(c, k)` | `c^k mod n²` | `k · m` |
| `Shift(c, Δ)` | `c · g^Δ mod n²` | `m + Δ` |

**Note**: `ScalarMul` and `Shift` differ in an important way:
- `ScalarMul(c, k)` exponentiates the ciphertext by scalar `k`, computing `c^k`. This multiplies the plaintext by `k` but also raises the randomness to the `k`-th power.
- `Shift(c, Δ)` multiplies by the representative `g^Δ`, adding `Δ` to the plaintext without changing the randomness component. This does not re-randomize the ciphertext.

## Usage

### Key Generation

```go
import "github.com/bronlabs/bron-crypto/pkg/encryption/paillier"

scheme := paillier.NewScheme()

// Generate with 2048-bit primes (4096-bit modulus)
kg, _ := scheme.Keygen(paillier.WithEachPrimeBitLen(2048))
sk, pk, _ := kg.Generate(rand.Reader)
```

### Encryption and Decryption

```go
enc, _ := scheme.Encrypter()
dec, _ := scheme.Decrypter(sk)

// Create plaintext from integer
ps := pk.PlaintextSpace()
pt, _ := ps.FromInt(value)

// Encrypt (returns ciphertext and nonce)
ct, nonce, _ := enc.Encrypt(pt, pk, rand.Reader)

// Decrypt
decrypted, _ := dec.Decrypt(ct)
```

### Homomorphic Addition and Subtraction

```go
// Given Enc(a) and Enc(b)
ct1, _, _ := enc.Encrypt(ptA, pk, rand.Reader)
ct2, _, _ := enc.Encrypt(ptB, pk, rand.Reader)

// Compute Enc(a + b)
ctSum := ct1.HomAdd(ct2)

// Compute Enc(a - b)
ctDiff := ct1.HomSub(ct2)
```

### Scalar Multiplication

```go
// Given Enc(m) and scalar k
ct, _, _ := enc.Encrypt(pt, pk, rand.Reader)
scalar := num.N().FromUint64(5)

// Compute Enc(k · m) via exponentiation: c^k
ctScaled := ct.ScalarMul(scalar)

// With bounded exponent for efficiency (when k fits in b bits)
ctScaled := ct.ScalarMulBounded(scalar, 16)
```

### Plaintext Shift

```go
// Given Enc(m) and plaintext delta Δ
delta, _ := ps.FromInt(deltaValue)

// Compute Enc(m + Δ) via multiplication by g^Δ
// Note: does not change the randomness component
ctShifted, _ := ct.Shift(pk, delta)
```

### Re-randomization

```go
// Produce unlinkable ciphertext encrypting the same value
// Multiplies by r'^n for fresh random r'
ctNew, nonce, _ := ct.ReRandomise(pk, rand.Reader)
```

### Self-Encryption (CRT Optimization)

When encrypting to your own key, use `SelfEncrypter` for ~3x speedup via CRT:

```go
se, _ := scheme.SelfEncrypter(sk)
ct, nonce, _ := se.SelfEncrypt(pt, rand.Reader)
```

### Batch Operations

```go
// Encrypt multiple plaintexts in parallel
plaintexts := []*paillier.Plaintext{pt1, pt2, pt3}
cts, nonces, _ := enc.EncryptMany(plaintexts, pk, rand.Reader)

// Self-encrypt multiple plaintexts
cts, nonces, _ := se.SelfEncryptMany(plaintexts, rand.Reader)
```

## Package Structure

| File | Contents |
|------|----------|
| `paillier.go` | `Scheme` type and factory methods |
| `keys.go` | `PrivateKey`, `PublicKey` |
| `plaintexts.go` | `PlaintextSpace`, `Plaintext` with arithmetic |
| `ciphertexts.go` | `CiphertextSpace`, `Ciphertext` with homomorphic ops |
| `nonces.go` | `NonceSpace`, `Nonce` |
| `participants.go` | `KeyGenerator`, `Encrypter`, `SelfEncrypter`, `Decrypter` |
| `cbor.go` | CBOR serialization |

## Security Notes

- Minimum key size enforced: 1024 bits per prime (2048-bit modulus)
- Production systems should use 2048+ bits per prime (4096+ bit modulus)
- `Shift` does not re-randomize; use `ReRandomise` when unlinkability is required
- Plaintexts use centred representation `[-n/2, n/2)` to support negative values
