# Krypton Rand

This package wraps a given prng reader (could be from `crypto/rand`) with a deterministic signing key as per [RFC8937](https://datatracker.ietf.org/doc/html/rfc8937), then uses it as an entropy source to the csprng which is either:
- AES-CTR-DRBG if the platfom supports hardware AES instructions (to ensure constant-time behavior)
- ChaCha20 with fast key erasure otherwise.

The result, can be used as a drop in replacement for `crypto/rand` or any other CSPRNG.
