# Hybrid Public Key Encryption (HPKE)

This package implements Hybrid Public Key Encryption as specified in [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html). HPKE provides public-key encryption of arbitrary-sized plaintexts with optional sender authentication.

For ECC-based encryption where threshold decryption is not required, this package should be used.

## Overview

HPKE combines an asymmetric Key Encapsulation Mechanism (KEM), a Key Derivation Function (KDF), and an Authenticated Encryption with Associated Data (AEAD) algorithm to provide hybrid public-key encryption.

### HPKE Modes

HPKE supports four modes with different authentication properties:

| Mode | Value | Sender Authentication | Description |
|------|-------|----------------------|-------------|
| Base | `0x00` | None | Encryption to a public key without sender authentication |
| PSK | `0x01` | Pre-shared key | Both parties share a secret key; recipient verifies sender possessed PSK |
| Auth | `0x02` | Asymmetric key | Sender's private key authenticates; provides non-repudiation |
| AuthPSK | `0x03` | Both | Combines PSK and asymmetric authentication for defence in depth |

### Supported Algorithms

**KEM (Key Encapsulation Mechanism):**
| ID | Algorithm | Nsecret | Nenc | Npk | Nsk |
|----|-----------|---------|------|-----|-----|
| `0x0010` | DHKEM(P-256, HKDF-SHA256) | 32 | 65 | 65 | 32 |
| `0x0020` | DHKEM(X25519, HKDF-SHA256) | 32 | 32 | 32 | 32 |

**KDF (Key Derivation Function):**
| ID | Algorithm | Nh |
|----|-----------|-----|
| `0x0001` | HKDF-SHA256 | 32 |
| `0x0003` | HKDF-SHA512 | 64 |

**AEAD (Authenticated Encryption):**
| ID | Algorithm | Nk | Nn | Nt |
|----|-----------|-----|-----|-----|
| `0x0001` | AES-128-GCM | 16 | 12 | 16 |
| `0x0002` | AES-256-GCM | 32 | 12 | 16 |
| `0x0003` | ChaCha20Poly1305 | 32 | 12 | 16 |
| `0xFFFF` | Export-only | N/A | N/A | N/A |

## Usage

### Creating a Cipher Suite and Scheme

```go
import (
    "crypto/rand"
    "github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
    "github.com/bronlabs/bron-crypto/pkg/encryption/hpke"
)

// Create cipher suite
suite, _ := hpke.NewCipherSuite(
    hpke.DHKEM_P256_HKDF_SHA256,
    hpke.KDF_HKDF_SHA256,
    hpke.AEAD_AES_128_GCM,
)

// Create scheme with P-256 curve
curve := p256.NewCurve()
scheme, _ := hpke.NewScheme(curve, suite)
```

### Base Mode (No Authentication)

```go
// Sender: encrypt to receiver's public key
senderCtx, _ := hpke.SetupBaseS(suite, receiverPk, info, rand.Reader)
ciphertext, _ := senderCtx.Seal(plaintext, aad)
capsule := senderCtx.Capsule // Send capsule + ciphertext to receiver

// Receiver: decrypt using private key and capsule
receiverCtx, _ := hpke.SetupBaseR(suite, receiverSk, capsule, info)
plaintext, _ := receiverCtx.Open(ciphertext, aad)
```

### PSK Mode (Pre-Shared Key Authentication)

```go
psk := make([]byte, 32) // At least 32 bytes of entropy
rand.Read(psk)
pskId := []byte("my-psk-identifier")

// Sender
senderCtx, _ := hpke.SetupPSKS(suite, receiverPk, psk, pskId, info, rand.Reader)
ciphertext, _ := senderCtx.Seal(plaintext, aad)

// Receiver (must have same PSK)
receiverCtx, _ := hpke.SetupPSKR(suite, receiverSk, capsule, psk, pskId, info)
plaintext, _ := receiverCtx.Open(ciphertext, aad)
```

### Auth Mode (Asymmetric Key Authentication)

```go
// Sender uses their private key for authentication
senderCtx, _ := hpke.SetupAuthS(suite, receiverPk, senderSk, info, rand.Reader)
ciphertext, _ := senderCtx.Seal(plaintext, aad)

// Receiver verifies sender's identity using sender's public key
receiverCtx, _ := hpke.SetupAuthR(suite, receiverSk, capsule, senderPk, info)
plaintext, _ := receiverCtx.Open(ciphertext, aad)
```

### AuthPSK Mode (Combined Authentication)

```go
// Sender: authenticated with both private key and PSK
senderCtx, _ := hpke.SetupAuthPSKS(suite, receiverPk, senderSk, psk, pskId, info, rand.Reader)
ciphertext, _ := senderCtx.Seal(plaintext, aad)

// Receiver: verifies both mechanisms
receiverCtx, _ := hpke.SetupAuthPSKR(suite, receiverSk, capsule, senderPk, psk, pskId, info)
plaintext, _ := receiverCtx.Open(ciphertext, aad)
```

### Multiple Messages with Same Context

A single context can encrypt/decrypt multiple messages. Each message uses a unique nonce derived from an internal sequence number:

```go
senderCtx, _ := hpke.SetupBaseS(suite, receiverPk, info, rand.Reader)
receiverCtx, _ := hpke.SetupBaseR(suite, receiverSk, senderCtx.Capsule, info)

// Messages must be decrypted in the same order they were encrypted
ct1, _ := senderCtx.Seal(msg1, nil)
ct2, _ := senderCtx.Seal(msg2, nil)
ct3, _ := senderCtx.Seal(msg3, nil)

pt1, _ := receiverCtx.Open(ct1, nil) // Must open ct1 first
pt2, _ := receiverCtx.Open(ct2, nil) // Then ct2
pt3, _ := receiverCtx.Open(ct3, nil) // Then ct3
```

### Secret Export

Derive additional secrets from the encryption context:

```go
exporterContext := []byte("application-specific-context")
length := 32

// Both sender and receiver derive the same secret
senderSecret, _ := senderCtx.Export(exporterContext, length)
receiverSecret, _ := receiverCtx.Export(exporterContext, length)
// senderSecret == receiverSecret
```

### High-Level Encrypter/Decrypter API

For simpler use cases:

```go
// Create encrypter with options
encrypter, _ := scheme.Encrypter(
    hpke.EncryptingWithApplicationInfo(info),
    hpke.EncryptingWithAuthentication(senderSk), // For Auth mode
)

ciphertext, capsule, _ := encrypter.Encrypt(plaintext, receiverPk, rand.Reader)

// Create decrypter
decrypter, _ := scheme.Decrypter(receiverSk,
    hpke.DecryptingWithCapsule(capsule),
    hpke.DecryptingWithApplicationInfo(info),
    hpke.DecryptingWithAuthentication(senderPk), // For Auth mode
)

plaintext, _ := decrypter.Decrypt(ciphertext)
```

### Using X25519 Instead of P-256

```go
import "github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"

curve := curve25519.NewPrimeSubGroup()
suite, _ := hpke.NewCipherSuite(
    hpke.DHKEM_X25519_HKDF_SHA256,
    hpke.KDF_HKDF_SHA256,
    hpke.AEAD_CHACHA_20_POLY_1305,
)
scheme, _ := hpke.NewScheme(curve, suite)
```

## Package Structure

| File | Contents |
|------|----------|
| `hpke.go` | `Scheme` type, type aliases, constants |
| `rfc.go` | RFC 9180 Setup functions (`SetupBaseS`, `SetupBaseR`, etc.) |
| `participants.go` | `Encrypter`, `Decrypter` and configuration options |
| `kem.go` | `KEM`, `DEM` for direct KEM operations |

## Security Notes

- **PSK entropy**: Pre-shared keys MUST have at least 32 bytes of entropy
- **Info binding**: The `info` parameter is cryptographically bound to the derived keys; mismatched `info` causes decryption failure
- **Sequence ordering**: Messages must be decrypted in the same order they were encrypted
- **Nonce uniqueness**: Each context maintains a sequence number to ensure unique nonces; never reuse a context after sequence overflow
- **AAD handling**: Associated data is authenticated but not encrypted; provide identical AAD during decryption
