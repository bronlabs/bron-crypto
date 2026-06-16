// Package dec implements CGGMP21 Figure 28, the Paillier special decryption in
// the exponent sigma protocol.
//
// CBOR unmarshalling validates local structure and nested type constructors.
// Contextual checks that depend on protocol parameters or statement/witness
// relations are performed by Protocol.ValidateStatement and Protocol.Verify.
package dec
