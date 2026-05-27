// Package elgamal implements the generalised ElGamal cryptosystem over any finite
// abelian cyclic group G in which the Decisional Diffie–Hellman problem is hard
// (typically a prime-order elliptic-curve group). The secret key is a scalar a,
// the public key is h = gᵃ, and a message m ∈ G is encrypted under nonce r as the
// pair (gʳ, m·hʳ); decryption recovers m = δ·γ⁻ᵃ. The scheme is IND-CPA under DDH
// and multiplicatively homomorphic — the product of two ciphertexts encrypts the
// product of the plaintexts under the sum of the nonces — which also makes it
// re-randomisable and shiftable. It is assembled from the internal "GIFT"
// group-homomorphic encryption framework.
//
// See README.md for details.
package elgamal
