// Package vanilla provides a configurable generic Schnorr signature implementation.
//
// Unlike BIP-340 or Mina which have fixed parameter choices, this package allows
// customization of all aspects of the Schnorr signature scheme:
//   - Elliptic curve group (any prime-order group)
//   - Hash function (SHA-256, SHA-3, BLAKE2, etc.)
//   - Response equation sign (s = k + ex or s = k - ex)
//   - Byte ordering (big-endian or little-endian)
//   - Nonce parity constraints (optional even-y requirement)
//
// This flexibility makes it suitable for implementing custom Schnorr variants
// or for use with non-standard curves.
//
// # Example Usage
//
//	scheme, _ := vanilla.NewScheme(
//	    secp256k1.NewCurve(),           // Curve
//	    sha256.New,                      // Hash function
//	    false,                           // Response operator not negative
//	    false,                           // Big-endian challenge elements
//	    nil,                             // No nonce parity constraint
//	    rand.Reader,                     // Random nonce generation
//	)
//	signer, _ := scheme.Signer(privateKey)
//	signature, _ := signer.Sign(message)
package vanilla
