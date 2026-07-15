// Package affg implements CGGMP21 Figure 25, the Paillier affine operation
// sigma protocol with a group commitment.
//
// CBOR unmarshalling validates local structure and nested type constructors.
// Contextual checks that depend on protocol parameters or statement/witness
// relations are performed by Protocol.ValidateStatement and Protocol.Verify.
//
// The simulator uses the standard honest-verifier sigma shape: sample a
// response for the fixed challenge, then reconstruct the commitment. CGGMP21
// leaves the affine-operation simulator implicit; this is analogous to the
// simulator construction used by encelg.
package affg
