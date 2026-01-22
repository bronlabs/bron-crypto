// Package zk implements a zero-knowledge compiler that transforms honest-verifier
// zero-knowledge (HVZK) sigma protocols into fully zero-knowledge interactive
// protocols using commitment schemes.
//
// The compiler adds a preliminary round where the verifier commits to the challenge
// before seeing the prover's commitment. This prevents a malicious verifier from
// choosing challenges adaptively, ensuring zero-knowledge against any verifier.
//
// The resulting protocol has 5 rounds:
//  1. Verifier commits to challenge
//  2. Prover sends commitment (a)
//  3. Verifier opens challenge commitment
//  4. Prover sends response (z)
//  5. Verifier verifies the proof
package zk
