// Package fac implements the CGGMP21 small-factor sigma protocol.
//
// CBOR unmarshalling validates local structure and nested type constructors.
// Contextual checks that depend on protocol parameters or statement/witness
// relations are performed by Protocol.ValidateStatement and Protocol.Verify.
//
// RunSimulator samples v symmetrically. Figure 26's HVZK text omits the
// leading signed range marker for v, but the honest value v = r - e*nu*p is
// signed, so the symmetric simulator distribution is intentional.
package fac
