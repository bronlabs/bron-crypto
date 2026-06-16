// Package encelg implements CGGMP21 Figure 24, the Paillier range proof with
// ElGamal-style group commitment.
//
// CBOR unmarshalling validates local structure and nested type constructors.
// Contextual checks that depend on protocol parameters or statement/witness
// relations are performed by Protocol.ValidateStatement and Protocol.Verify.
package encelg
