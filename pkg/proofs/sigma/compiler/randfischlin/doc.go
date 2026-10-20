// Package randfischlin implements the randomised variant of Fischlin's transform
// of Kondi and shelat for compiling interactive sigma protocols into
// non-interactive zero-knowledge proofs with straight-line extraction.
//
// The prover steps through the challenge space in random order instead of
// counting up from zero, which removes Fischlin's quasi-unique responses
// requirement and makes the transform applicable to every strongly special
// sound sigma protocol, including OR compositions.
//
// The parameters r (repetitions), l (hash output bits) and t (challenge bits)
// are derived from the sigma protocol's special soundness n: r = 16 is fixed and
// l = ceil(128 / r) + ceil(log2(n - 1)), so that the knowledge error stays at
// 2^(-128) for n-special sound protocols such as batch proofs. For n = 2 this is
// the fixed parameter set of the paper (l = 8, t = 56).
//
// Reference: "Improved Straight-Line Extraction in the Random Oracle Model With
// Applications to Signature Aggregation" by Kondi and shelat (Figure 9), and
// Section 5.1 of "Optimising and Implementing Fischlin's Transform for UC-Secure
// Zero Knowledge" by Chen and Lindell for the n-special soundness rule.
package randfischlin
