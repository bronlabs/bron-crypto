// Package encryption defines the scheme-agnostic interfaces, error sentinels, and
// generic helpers shared by the concrete public-key encryption schemes in its
// subpackages. A scheme encrypts a Plaintext under a freshly sampled secret Nonce
// to produce a public Ciphertext; the matching DecryptionKey recovers the
// plaintext, and an OpeningKey additionally recovers the nonce.
//
// EncryptionKey is the public-key capability common to every scheme; DecryptionKey
// and OpeningKey add the private-key trapdoors. The Homomorphic and
// GroupHomomorphic variants describe schemes whose plaintexts, nonces, and
// ciphertexts can be combined algebraically, so one can compute on ciphertexts
// without decrypting. Group-homomorphic schemes follow the "GIFT" structure, in
// which a ciphertext factors as Representative(plaintext) · IdentityNoise(nonce).
//
// Implementations: elgamal (multiplicatively homomorphic, IND-CPA under DDH over a
// prime-order group) and paillier (additively homomorphic, IND-CPA under DCRA over
// Z*_{N²}).
//
// See README.md for details.
package encryption
