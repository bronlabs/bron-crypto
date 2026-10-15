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
// Variants, schemes, signers, and verifiers are runtime objects without a supported
// persistence format. Persist keys, shards, signatures, and protocol messages
// separately and reconstruct runtime objects using their constructors.
// Private-key CBOR uses separate privateKey and publicKey fields; the earlier
// reflection-based encoding omitted the public point and is no longer accepted.
//
// # Threshold Signatures
//
// The framework supports threshold/MPC-friendly signatures through additional
// interfaces that handle parity corrections required by variants like BIP-340.
//
// # API Migration to Stateless Variants
//
// Variants now retain only fixed algorithm configuration. Callers migrating from
// the stateful API must make the following changes:
//   - Variant.ComputeNonceCommitment takes the private key, message, and io.Reader
//     explicitly. For Mina, a nil reader selects deterministic derivation; a
//     non-nil reader selects random sampling. BIP-340 requires a reader for aux data.
//   - Variant.ComputeResponse takes the public key before the private scalar,
//     nonce, and challenge. For MPC, pass the aggregate public key and unadjusted
//     secret share; the method applies any required secret-share parity correction.
//     CorrectAdditiveSecretShareParity has been removed from MPCFriendlyVariant
//     and all variant implementations.
//   - SignerTrait.Sign takes a randomness reader after the message. Concrete
//     signers still expose Sign(message).
//   - mina.NewScheme(nid) and mina.NewLegacyScheme(nid) return only *Scheme.
//     Supply the private key to Scheme.Signer instead of the scheme constructor.
//   - Replace Mina's NewDeterministicVariant and NewRandomisedVariant with
//     NewVariant, and their NewLegacyDeterministicVariant and
//     NewLegacyRandomisedVariant counterparts with NewLegacyVariant. Pass signing
//     inputs to ComputeNonceCommitment; IsDeterministic has been removed.
//   - bip340.Variant.Aux has been removed. Use bip340.NewSchemeWithAux for fixed
//     auxiliary data, or supply a reader directly to ComputeNonceCommitment.
//
// References:
//   - Schnorr, C.P. (1991). Efficient signature generation by smart cards.
//     Journal of Cryptology, 4(3), 161-174.
//   - Fiat, A., & Shamir, A. (1987). How to prove yourself: Practical solutions
//     to identification and signature problems.
package schnorrlike
