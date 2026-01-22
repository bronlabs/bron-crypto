// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm (ECDSA)
// as specified in FIPS 186-5 and SEC 1, Version 2.0.
//
// ECDSA is a widely-used digital signature scheme based on elliptic curve cryptography.
// It provides the same level of security as RSA but with smaller key sizes, making it
// efficient for constrained environments.
//
// This implementation supports:
//   - Standard randomised ECDSA (requires secure random source)
//   - Deterministic ECDSA per RFC 6979 (no random source needed)
//   - Public key recovery from signatures (Bitcoin-style recovery ID)
//   - Signature normalisation to low-S form (BIP-62 compatible)
//
// References:
//   - FIPS 186-5: https://csrc.nist.gov/pubs/fips/186-5/final
//   - SEC 1 v2.0: https://www.secg.org/sec1-v2.pdf
//   - RFC 6979: https://www.rfc-editor.org/rfc/rfc6979
package ecdsa
