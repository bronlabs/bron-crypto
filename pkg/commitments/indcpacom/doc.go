// Package indcpacom builds a commitment scheme from an IND-CPA secure encryption
// scheme: a commitment to message m with witness (nonce) r is the ciphertext
// Enc_ek(m; r) under a public encryption key ek. It is computationally hiding,
// under the IND-CPA security of the encryption scheme, and binding on the message,
// because a ciphertext decrypts to at most one plaintext — the dual of Pedersen's
// perfectly-hiding / computationally-binding tradeoff. Hiding holds only against
// parties that do not hold the decryption key; that key is a trapdoor which
// recovers the committed message (and, with an opening key, the witness), making
// the construction an extractable commitment. When the encryption scheme is
// homomorphic, HomomorphicCommitmentKey lifts that homomorphism to commitments.
//
// See README.md for details.
package indcpacom
