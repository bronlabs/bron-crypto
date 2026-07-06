// Package signing implements the online CGGMP21 threshold ECDSA signing
// protocol.
//
// The runner executes the four online signing rounds and returns the local
// partial signature together with a session-bound aggregator. If the round 4
// consistency checks fail, the runner enters the internal red-alert path and
// verifies the disclosure proofs needed for identifiable abort.
package signing
