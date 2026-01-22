// Package sigor implements OR composition of sigma protocols.
//
// OR composition allows a prover to demonstrate knowledge of a witness for at least one
// of n statements, without revealing which statement they know the witness for.
// This provides witness indistinguishability - the verifier cannot determine which
// branch the prover actually knows.
//
// The composition uses the XOR technique: challenges for all branches XOR together
// to equal the verifier's challenge. The prover runs the real protocol for the branch
// they know, and simulates the other branches using the simulator.
package sigor
