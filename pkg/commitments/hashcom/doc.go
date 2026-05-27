// Package hashcom provides a hash-based commitment scheme. A commitment is the
// keyed hash of the message concatenated with a fresh random witness,
// H_k(message || witness), where the key k is a public parameter. Binding
// reduces to the collision resistance of the keyed hash and hiding to the
// entropy of the secret witness. The scheme is non-interactive, non-homomorphic,
// and has no trapdoor.
//
// See README.md for details.
package hashcom
