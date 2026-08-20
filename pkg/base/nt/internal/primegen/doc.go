// Package primegen implements the sieved, exactly-uniform prime generator
// shared by every prime-generation entry point in pkg/base/nt.
//
// The generator answers requests of the form "a uniformly random prime of
// exactly `bits` bits with structural class C", where C is one of
//
//	Plain — an odd prime with no further structure,
//	Blum  — a prime ≡ 3 (mod 4),
//	Safe  — a prime q ≡ 3 (mod 4) with (q−1)/2 also prime,
//
// optionally restricted to [lo, 2^bits) for a caller-supplied lower bound lo
// (used by pair generation to enforce FIPS 186-5 A.1.1's √2·2^(bits−1)
// bound at candidate level, where a rejection costs microseconds instead of
// a discarded multi-second prime).
//
// # Candidate construction (the sieve)
//
// A prime of class C can only occupy certain residue classes modulo small
// primes: q mod p ≠ 0 for every small prime p (else q is composite), and
// for Safe additionally q mod p ≠ 1 (else p divides (q−1)/2) and
// q ≡ 3 (mod 4) (else (q−1)/2 is even). Rather than sampling random numbers
// and trial-dividing, candidates are assembled from independently sampled
// admissible residues via the Chinese Remainder Theorem — following the
// constructive candidate generation of Clavier, Feix, Thierry & Paillier,
// "Generating Provable Primes Efficiently on Embedded Devices" (PKC 2012),
// Section 3 — so every candidate passes the CRT sieve by construction:
//
//	q = (offset + Σᵢ rᵢ·basisᵢ mod m) + b·m,   m = 2Π or 4Π,  Π = Π pᵢ,
//
// with rᵢ uniform over the admissible residues of pᵢ, b uniform over the
// ⌈2^bits/m⌉ windows tiling [0, 2^bits), and the candidate rejected unless
// it lies in [lo, 2^bits). Because (x, b) ↔ q is a bijection and every
// component is uniform, accepted candidates are exactly uniform over the
// admissible set — a superset of all class-C primes in range — and the
// output is therefore exactly uniform over all class-C primes in range.
// This deliberately replaces the Joye-Paillier safe-prime generator (CHES
// 2006), whose quadratic-non-residue sieve loses ≈ 1 bit of output entropy
// per sieve prime (audit finding TOB-BLCG-4).
//
// Π is capped at 2^(bits−11), which admits the first ~181 table primes at
// 1536 bits. The remaining table primes cannot be folded into the CRT
// modulus, so surviving candidates are additionally trial-divided against
// them (in uint64-packed groups, cheapest-first) up to a bit-length-scaled
// cutoff — rejecting as many candidates as economically possible before the
// comparatively very expensive probabilistic primality tests run.
//
// # Testing and parallelism
//
// Survivors are tested with a two-stage strategy: BPSW (ProbablyPrime(0))
// as the cheap filter — on (q−1)/2 first for Safe, since that rejects
// almost all candidates — then the caller-supplied FIPS 186-5 Appendix C
// Miller-Rabin round counts for the formal error bound.
//
// The search is a pipeline: the calling goroutine reads all candidate
// entropy from the PRNG sequentially and slices it into numbered fixed-size
// jobs; parallel workers — scaled to the expected search size, up to one per
// CPU core — turn jobs into candidates and test them, never touching the
// PRNG; the calling goroutine folds results back in canonical job order and
// cancels the workers once it has what the request needs (one prime, or two
// with the FIPS pair filters). Consuming successes in canonical order rather
// than completion order is load-bearing: completion time is value-dependent
// (BPSW's Lucas parameter search), and taking the temporally-first success
// measurably biases small-bit-length outputs toward fast-verifying residue
// classes (guarded by TestGenerate_SafeUniformityChiSquared).
//
// Because only the calling goroutine reads the PRNG, a single generation
// call needs no concurrent-safe reader. A PRNG shared across CONCURRENT
// generation calls must still be safe for concurrent use (e.g.
// crypto/rand.Reader, or a wrapper such as csprng.NewThreadSafePrng); this
// package deliberately does not lock the reader itself — a per-call lock
// cannot protect a PRNG the caller shares with other concurrent calls, and
// would only disguise that requirement.
package primegen
