// Package schnorrlike provides a generic framework for Schnorr-like signature schemes.
//
// Schnorr signatures are digital signatures based on the discrete logarithm problem,
// originally proposed by Claus-Peter Schnorr in 1989. They convert an interactive
// identification protocol into a non-interactive signature scheme using the
// Fiat-Shamir heuristic.
//
// # Protocol Overview
//
// A Schnorr signature on message m with private key x and public key P = x·G consists of:
//  1. Generate random nonce k and compute commitment R = k·G
//  2. Compute challenge e = H(R || P || m)
//  3. Compute response s = k + e·x (or s = k - e·x depending on variant)
//
// The signature is (R, s) or (e, s) depending on the variant.
//
// Verification checks: s·G = R + e·P (or s·G = R - e·P for negative response variants)
//
// # Variants
//
// This package supports multiple Schnorr variants through the Variant interface:
//   - BIP-340: Bitcoin's Schnorr with x-only public keys and tagged hashing
//   - Mina: Schnorr on Pallas curve with Poseidon hashing
//   - Vanilla: Configurable generic Schnorr implementation
//
// Each variant can customise nonce generation, challenge computation, and response
// calculation while sharing common verification logic.
//
// # Threshold Signatures
//
// The framework supports threshold/MPC-friendly signatures through additional
// interfaces that handle parity corrections required by variants like BIP-340.
//
// References:
//   - Schnorr, C.P. (1991). Efficient signature generation by smart cards.
//     Journal of Cryptology, 4(3), 161-174.
//   - Fiat, A., & Shamir, A. (1987). How to prove yourself: Practical solutions
//     to identification and signature problems.
package schnorrlike
