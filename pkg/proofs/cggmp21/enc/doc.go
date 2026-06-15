// Package enc implements CGGMP21 Figure 11, the Paillier Encryption in Range
// sigma protocol Πenc.
//
// CBOR unmarshalling validates local structure and nested type constructors.
// Contextual checks that depend on protocol parameters or statement/witness
// relations are performed by Protocol.ValidateStatement and Protocol.Verify.
package enc
