// Package rvole_mrr21 instantiates the random vector OLE core of rvole with
// the ξ OTs run directly as one batch of the one-round-trip endemic base OT of
// MRR21, with 256-bit messages and no OT extension. DKLs23 proves the rVOLE in
// the endemic OT hybrid, so base OTs satisfy its assumptions as they are; what
// the extension removes is cost, not a security requirement. Without the
// extension there is no correlation Δ to leak through selective failure, and
// every OT output is its own HKDF derivation.
//
// Rounds: in round 1 both parties send their base-OT message at once; in
// round 2 Bob derives his rows and b, and Alice derives her output pairs and
// sends the multiplication message; in round 3 Bob verifies and outputs d.
package rvole_mrr21
