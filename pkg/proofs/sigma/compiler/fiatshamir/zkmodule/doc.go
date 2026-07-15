// Package zkmodule implements the non-interactive ZK module of CGGMP21
// (Figure 3): the Fiat-Shamir transform of a sigma protocol in the
// random-oracle model.
//
// A sigma protocol's three messages are (a) the prover's commitment, (e) the
// verifier's random challenge, and (z) the prover's response. The transform
// removes interaction by deriving e from a hash of the session transcript over
// (statement, a) instead of from the verifier. Because the hash is modelled as
// a random oracle, the resulting proof is sound and zero-knowledge whenever the
// underlying sigma protocol is honest-verifier zero-knowledge with a
// sufficiently small soundness error.
//
// Unlike a textbook Fiat-Shamir transform, this module splits commitment
// generation (Commit) from challenge derivation and response (Prove). Exposing
// the commitment as a separate step lets a caller absorb it into a larger
// protocol transcript before the challenge is fixed, which is the structure
// CGGMP21 relies on for straight-line witness extraction without the forking
// lemma.
//
// This package is the engine behind the fiatshamir compiler and is not intended
// to be used directly; callers should go through that compiler, which adds
// session-level domain separation and the soundness-parameter check required
// for non-interactive security.
package zkmodule
