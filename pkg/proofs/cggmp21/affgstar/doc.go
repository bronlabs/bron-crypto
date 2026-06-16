// Package affgstar implements CGGMP21 Figure 27, the setup-less Paillier
// affine operation sigma protocol with a group commitment.
//
// CBOR unmarshalling validates local structure and nested type constructors.
// Contextual checks that depend on protocol parameters or statement/witness
// relations are performed by Protocol.ValidateStatement and Protocol.Verify.
package affgstar
