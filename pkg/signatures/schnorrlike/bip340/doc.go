// Package bip340 implements BIP-340 Schnorr signatures for Bitcoin.
//
// BIP-340 defines a Schnorr signature scheme over the secp256k1 curve with
// specific design choices optimised for Bitcoin:
//
// # Key Features
//
//   - X-only public keys: Only the x-coordinate is used (32 bytes vs 33 compressed)
//   - Even y-coordinate constraint: R and P are implicitly lifted to have even y
//   - Tagged hashing: Domain-separated SHA-256 for aux, nonce, and challenge
//   - Deterministic nonce: k derived from private key, message, and auxiliary randomness
//
// # Signature Format
//
// A BIP-340 signature is 64 bytes: (R.x || s) where:
//   - R.x: 32-byte x-coordinate of the nonce commitment
//   - s: 32-byte response scalar
//
// # Security Properties
//
// The auxiliary randomness input protects against:
//   - Differential fault attacks
//   - Differential power analysis
//   - Nonce reuse with same message but different auxiliary data
//
// # Batch Verification
//
// BIP-340 supports efficient batch verification using random linear combinations,
// providing significant speedups when verifying multiple signatures.
//
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
package bip340
