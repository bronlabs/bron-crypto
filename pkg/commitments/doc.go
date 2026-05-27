// Package commitments defines the scheme-agnostic interfaces and helpers shared by
// the concrete commitment schemes in its subpackages. A commitment binds a message
// under a secret witness so it can be revealed (opened) later without being changed
// beforehand; the two security goals are hiding (the commitment leaks nothing about
// the message) and binding (it cannot be opened to a second message).
//
// CommitmentKey is the public parameter common to every scheme; TrapdoorKey adds a
// secret that allows equivocation (used by simulators); the Homomorphic and
// GroupHomomorphic variants describe schemes whose messages, witnesses, and
// commitments can be combined algebraically. The generic Commit and ReRandomise
// helpers work against any conforming key.
//
// Implementations: pedersen (perfectly hiding, computationally binding over a
// prime-order group), intcom (CGGMP21 ring-Pedersen integer commitment),
// indcpacom (computationally hiding, binding-by-decryption from any IND-CPA
// encryption scheme), and hashcom (hash-based).
//
// See README.md for details.
package commitments
