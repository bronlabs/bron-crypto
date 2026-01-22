// Package indcpacom implements a commitment scheme based on IND-CPA secure encryption.
// Any IND-CPA (indistinguishability under chosen-plaintext attack) secure encryption
// scheme can be transformed into a commitment scheme where:
//   - Commit(m) = Encrypt(m, r) using randomness r as the witness
//   - The commitment is the ciphertext
//   - The witness is the encryption nonce/randomness
//
// This construction inherits the hiding property from the semantic security of the
// encryption scheme and the binding property from the correctness of decryption.
package indcpacom
