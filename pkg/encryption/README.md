# Encryption

This package defines the common interfaces, error sentinels, and generic helpers
for public-key encryption schemes; the concrete schemes live in subpackages.

A scheme encrypts a **plaintext** `m` under a freshly sampled secret **nonce** `r`
to produce a public **ciphertext** `c`. The holder of the private key recovers `m`
(and, with an opening key, also `r`). Encryption under a fixed nonce is
deterministic — which lets a verifier recompute a ciphertext — so hiding depends on
the nonce being fresh, uniform, and secret. Reusing a nonce under the same key
generally breaks security.

## Core interfaces

- `EncryptionKey`: the public key. `EncryptWithNonce(m, r)` encrypts
  deterministically; `SampleNonce` draws fresh randomness; `Type` names the scheme.
- `DecryptionKey`: the private key. Adds `Decrypt(c) → m` and `Public()`.
- `OpeningKey`: a private key that also recovers the nonce — `Open(c) → (m, r)`. This
  stronger capability is used by simulators and to make encryption-based commitments
  extractable.
- `Homomorphic` / `GroupHomomorphic`: schemes where plaintexts, nonces, and
  ciphertexts carry algebraic operations and encryption is a homomorphism, so
  ciphertexts can be combined (`CiphertextOp`), scaled (`CiphertextScalarOp`),
  shifted (`Shift`), and re-randomised (`ReRandomise`) without decrypting. The
  `GroupHomomorphic` variant exposes the underlying groups and follows the GIFT
  structure: every ciphertext factors as `Representative(m) · IdentityNoise(r)`.
- The `Homomorphic…Key` combinations layer these onto the key types.

`Plaintext`, `Nonce`, and `Ciphertext` are the (scheme-defined) message, randomness,
and output types; the nonce is secret, the ciphertext is public.

## Helpers

- `Encrypt(m, key, prng)`: samples a fresh nonce and returns `(ciphertext, nonce)`.
- `EncryptMany`: encrypts a batch concurrently, each under a fresh nonce. **The
  shared `prng` must be safe for concurrent use** (e.g. `crypto/rand.Reader`); a
  non-concurrency-safe source can race and hand out duplicate nonces. Use
  `EncryptManyWithNonces` when supplying your own nonces.
- `DecryptMany` / `OpenMany`: batch decrypt / open, preferring a scheme's own batched
  implementation (e.g. CRT batching) when available.

## Implementations

- `elgamal` — `(g^r, m·h^r)` over a prime-order group. IND-CPA under DDH;
  multiplicatively homomorphic.
- `paillier` — `(1+N)^m · r^N mod N²` over `Z*_{N²}`. IND-CPA under DCRA; additively
  homomorphic.

The internal `gift` package provides the shared group-homomorphic encryption
machinery (`Representative` · `IdentityNoise`) both schemes are built on.
