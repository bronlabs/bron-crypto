// Package elgamal implements the Generalized ElGamal cryptosystem over any
// finite abelian cyclic group, following section 8.4 of the Handbook of Applied
// Cryptography (Menezes, van Oorschot, Vanstone).
//
// The scheme is group-homomorphic: component-wise multiplication of two
// ciphertexts yields an encryption of the product of the underlying plaintexts.
// This makes it suitable as a building block in MPC protocols, threshold
// decryption, and verifiable shuffle constructions.
//
// Security is IND-CPA under the Decisional Diffie-Hellman (DDH) assumption in
// the underlying group. The scheme is malleable (not IND-CCA2); protocols that
// require ciphertext integrity must add an authentication layer (e.g.
// Cramer-Shoup, or a ZK proof of ciphertext well-formedness).
//
// See README.md for usage examples and a summary of the homomorphic operations.
package elgamal
