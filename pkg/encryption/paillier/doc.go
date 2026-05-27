// Package paillier implements the Paillier cryptosystem (Scheme 1 of Paillier99)
// over a modulus N = p·q. A message m ∈ Z_N is encrypted under a nonce r ∈ Z*_N as
// the ciphertext c = (1+N)^m · r^N mod N², an element of Z*_{N²}; decryption uses
// the factorisation (the secret key) via the CRT. The scheme is IND-CPA under the
// Decisional Composite Residuosity assumption and additively homomorphic — the
// product of two ciphertexts encrypts the sum of the plaintexts, and a ciphertext
// raised to k encrypts k·m — which also makes it re-randomisable and shiftable. It
// is assembled from the internal "GIFT" group-homomorphic framework, with CRT
// decryption optimised via Fermat's quotients.
//
// See README.md for details.
package paillier
