// Package bls implements BLS (Boneh-Lynn-Shacham) digital signatures as specified in
// draft-irtf-cfrg-bls-signature-06.
//
// BLS signatures are built on pairing-friendly elliptic curves and support signature aggregation,
// where multiple signatures can be combined into a single compact signature while maintaining
// cryptographic security. This implementation supports the BLS12-381 curve family.
//
// The package provides three signature schemes for rogue key attack prevention:
//   - Basic: requires all messages in an aggregate to be distinct
//   - Message Augmentation: prepends the public key to each message before signing
//   - Proof of Possession (POP): requires signers to prove knowledge of their secret key
//
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html
package bls
