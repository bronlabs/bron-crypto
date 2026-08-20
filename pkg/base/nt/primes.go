package nt

import (
	crand "crypto/rand"
	"io"
	"maps"
	"math/big"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal/primegen"
)

// PrimeSamplable constrains the target structure a freshly sampled prime is
// lifted into.
type PrimeSamplable[E algebra.NatPlusLike[E]] algebra.UnsignedNumericStructure[E]

// PrimeSampler is the signature of a single-prime sampling strategy. Different
// strategies impose different structural constraints on the output prime
// (unrestricted, Blum, safe, etc.) which in turn determine the cryptographic
// properties of any modulus built from a pair of such primes.
type PrimeSampler[E algebra.NatPlusLike[E]] func(set PrimeSamplable[E], bits uint, prng io.Reader) (E, error)

// MillerRabinChecks returns the number of Miller-Rabin rounds appropriate for
// primes of the given bit length. The table is indexed by bit length and
// targets the standard false-acceptance bound for cryptographic primes; for
// bit lengths below the smallest tabulated entry it falls back to a floor of
// StatisticalSecurityBits/4 rounds to preserve the security parameter.
func MillerRabinChecks(bits uint) int {
	if len(millerRabinIterations) == 0 {
		panic("millerRabinIterations is not initialised")
	}
	sortedKeys := slices.Sorted(maps.Keys(millerRabinIterations))

	// Case 1: bits smaller than the smallest table entry.
	if bits < sortedKeys[0] {
		return max(
			base.StatisticalSecurityBits/4,
			millerRabinIterations[sortedKeys[0]],
		)
	}

	// Case 2: find the largest key <= bits and return its value.
	for i := len(sortedKeys) - 1; i >= 0; i-- {
		if bits >= sortedKeys[i] {
			return millerRabinIterations[sortedKeys[i]]
		}
	}
	panic("millerRabinIterations is not properly initialised")
}

// GeneratePrime samples a uniformly random prime of exactly the requested
// bit length — every prime in [2^(bits-1), 2^bits) is equally likely. The
// prime is found with the sieved generator in internal/primegen: candidates
// are constructed coprime to a product of small primes by Chinese
// remaindering, trial-divided against further small primes, and only the
// survivors pay for probabilistic primality tests. Exception: below the
// sieve minimum (bits < 16, test-only sizes) it falls back to
// crypto/rand.Prime, which sets the top two bits and is therefore NOT
// uniform over the full range.
//
// prng is read sequentially by the calling goroutine only; it must be safe
// for concurrent use just when shared across concurrent generation calls
// (crypto/rand.Reader is; csprng.NewThreadSafePrng wraps one that isn't).
func GeneratePrime[E algebra.NatPlusLike[E]](set PrimeSamplable[E], bits uint, prng io.Reader) (E, error) {
	if set == nil {
		return *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if prng == nil {
		return *new(E), ErrIsNil.WithMessage("nil prng")
	}
	if bits < primegen.MinBits {
		// Below the sieve minimum: fall back to crypto/rand.Prime with the
		// FIPS-count Miller-Rabin double check.
		p, err := tinyPrime(bits, prng)
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("failed to generate prime")
		}
		return liftPrime(set, p)
	}
	p, err := primegen.Generate(primegen.Plain, bits, nil, testRounds(bits), prng)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("failed to generate prime")
	}
	return liftPrime(set, p)
}

// GeneratePrimePair samples an RSA-style prime pair (p, q) whose product has
// exactly keyLen bits. Each prime has bit length keyLen/2 and is sampled
// uniformly subject to the prime-selection constraints of FIPS 186-5 A.1.1
// (conditions 2(b)-2(d)): p, q ≥ ⌈√2·2^(keyLen/2−1)⌉ (so N = pq has full
// length) and |p − q| > 2^(keyLen/2−100) (Fermat-factorisation distance).
// A.1.1's public-exponent conditions (1, 2(a), 3) concern an RSA exponent
// pair and do not apply to this exponent-less API. No further structural
// constraint (such as p ≡ 3 mod 4 or (p−1)/2 prime) is imposed. Below the
// sieve minimum (keyLen < 32, test-only sizes) the crypto/rand.Prime
// fallback applies — see GeneratePrime.
//
// prng is read sequentially by the calling goroutine only; it must be safe
// for concurrent use just when shared across concurrent generation calls
// (crypto/rand.Reader is; csprng.NewThreadSafePrng wraps one that isn't).
func GeneratePrimePair[N algebra.NatPlusLike[N]](set PrimeSamplable[N], keyLen uint, prng io.Reader) (p, q N, err error) {
	var nilN N
	if keyLen/2 < primegen.MinBits {
		if set == nil {
			return nilN, nilN, ErrIsNil.WithMessage("nil structure")
		}
		if prng == nil {
			return nilN, nilN, ErrIsNil.WithMessage("nil prng")
		}
		if keyLen%2 != 0 {
			return nilN, nilN, ErrInvalidArgument.WithMessage("keyLen must be even")
		}
		return generateTinyPrimePair(set, keyLen, prng)
	}
	return generatePair(set, primegen.Plain, keyLen, prng)
}

// GenerateBlumPrime samples a uniformly random prime p of the requested bit
// length with p ≡ 3 (mod 4) (a "Blum" prime). In Z/pZ with p ≡ 3 mod 4, -1
// is a quadratic non-residue, so exactly one of {x, -x} is a quadratic
// residue for every x ∈ Z/pZ*. Products of two Blum primes form Blum
// integers, on which ZK arguments such as CGGMP21's Π^{mod} rely.
//
// prng is read sequentially by the calling goroutine only; it must be safe
// for concurrent use just when shared across concurrent generation calls
// (crypto/rand.Reader is; csprng.NewThreadSafePrng wraps one that isn't).
func GenerateBlumPrime[E algebra.NatPlusLike[E]](set PrimeSamplable[E], bits uint, prng io.Reader) (E, error) {
	if set == nil {
		return *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if prng == nil {
		return *new(E), ErrIsNil.WithMessage("nil prng")
	}
	if bits < primegen.MinBits {
		return *new(E), ErrInvalidArgument.WithMessage("blum prime size must be at least 16-bits")
	}
	p, err := primegen.Generate(primegen.Blum, bits, nil, testRounds(bits), prng)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("failed to generate blum prime")
	}
	return liftPrime(set, p)
}

// GenerateBlumPrimePair samples a pair of Blum primes (each ≡ 3 mod 4) of
// half the given keyLen each, whose product N = pq is a Blum integer of
// bit length keyLen. Blum integers enjoy the key property that squaring
// is a 4-to-1 map on Z/NZ* whose image is precisely QR_N, giving QR_N a
// canonical set of representatives — used both by Paillier-Blum ZK proofs
// and by Rabin-style commitments. The pair satisfies the same FIPS 186-5
// A.1.1 bounds as GeneratePrimePair.
//
// prng is read sequentially by the calling goroutine only; it must be safe
// for concurrent use just when shared across concurrent generation calls
// (crypto/rand.Reader is; csprng.NewThreadSafePrng wraps one that isn't).
func GenerateBlumPrimePair[E algebra.NatPlusLike[E]](set PrimeSamplable[E], keyLen uint, prng io.Reader) (p, q E, err error) {
	if keyLen < 2*primegen.MinBits {
		return *new(E), *new(E), ErrInvalidArgument.WithMessage("blum prime pair size must be at least 32-bits")
	}
	return generatePair(set, primegen.Blum, keyLen, prng)
}

// GenerateSafePrime samples a uniformly random safe prime of exactly the
// requested bit length: a prime q ≡ 3 (mod 4) with (q−1)/2 also prime.
// Every safe prime in [2^(bits-1), 2^bits) is equally likely — the sieved
// generator in internal/primegen restricts candidate residues modulo each
// sieve prime only to the classes a safe prime can actually occupy, so its
// output carries no structural bias (this replaced the Joye-Paillier
// generator, whose quadratic-non-residue sieve lost ≈ 1 bit of entropy per
// sieve prime — audit finding TOB-BLCG-4).
//
// prng is read sequentially by the calling goroutine only; it must be safe
// for concurrent use just when shared across concurrent generation calls
// (crypto/rand.Reader is; csprng.NewThreadSafePrng wraps one that isn't).
func GenerateSafePrime[E algebra.NatPlusLike[E]](set PrimeSamplable[E], bits uint, prng io.Reader) (E, error) {
	if set == nil {
		return *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if prng == nil {
		return *new(E), ErrIsNil.WithMessage("nil prng")
	}
	if bits < primegen.MinBits {
		return *new(E), ErrInvalidArgument.WithMessage("safe prime size must be at least 16-bits")
	}
	p, err := primegen.Generate(primegen.Safe, bits, nil, testRounds(bits), prng)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("failed to generate safe prime")
	}
	return liftPrime(set, p)
}

// GenerateSafePrimePair samples two independent safe primes p, q of half the
// given keyLen each. The resulting modulus N = pq is used wherever a strong
// RSA modulus is required: ring-Pedersen commitments, proofs over QR_N with
// prime-order structure, and range proofs that rely on the discrete log
// assumption in QR_N being hard. The pair satisfies the same FIPS 186-5
// A.1.1 bounds as GeneratePrimePair.
//
// prng is read sequentially by the calling goroutine only; it must be safe
// for concurrent use just when shared across concurrent generation calls
// (crypto/rand.Reader is; csprng.NewThreadSafePrng wraps one that isn't).
func GenerateSafePrimePair[E algebra.NatPlusLike[E]](set PrimeSamplable[E], keyLen uint, prng io.Reader) (p, q E, err error) {
	if keyLen < 2*primegen.MinBits {
		return *new(E), *new(E), ErrInvalidArgument.WithMessage("safe prime pair size must be at least 32-bits")
	}
	return generatePair(set, primegen.Safe, keyLen, prng)
}

// testRounds returns the FIPS 186-5 Appendix C Miller-Rabin round counts for
// a prime of the given bit length: Q for the prime itself and Half for its
// Sophie-Germain half (q−1)/2, which has one bit fewer. Half is consumed
// only by the Safe class.
func testRounds(bits uint) primegen.Rounds {
	return primegen.Rounds{
		Q:    MillerRabinChecks(bits),
		Half: MillerRabinChecks(bits - 1),
	}
}

// liftPrime converts a freshly generated prime into the caller's structure.
func liftPrime[E algebra.NatPlusLike[E]](set PrimeSamplable[E], p *big.Int) (E, error) {
	out, err := set.FromBytesBE(p.Bytes())
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("cannot convert prime to structure")
	}
	return out, nil
}

// generatePair drives primegen.GeneratePair for the given class with the
// FIPS 186-5 A.1.1 bounds applied where a rejection is cheapest: candidates
// below ⌈√2·2^(keyLen/2−1)⌉ are rejected before any primality test (2(b) —
// this is what guarantees N = pq has exactly keyLen bits), and the
// |p − q| > 2^(keyLen/2−100) distance condition (2(d)) is enforced by the
// pair collector.
func generatePair[N algebra.NatPlusLike[N]](set PrimeSamplable[N], class primegen.Class, keyLen uint, prng io.Reader) (p, q N, err error) {
	var nilN N
	if set == nil {
		return nilN, nilN, ErrIsNil.WithMessage("nil structure")
	}
	if prng == nil {
		return nilN, nilN, ErrIsNil.WithMessage("nil prng")
	}
	if keyLen%2 != 0 {
		return nilN, nilN, ErrInvalidArgument.WithMessage("keyLen must be even")
	}
	primeBits := keyLen / 2

	pBig, qBig, err := primegen.GeneratePair(class, primeBits, fipsPairLowerBound(keyLen), testRounds(primeBits), prng)
	if err != nil {
		return nilN, nilN, errs.Wrap(err).WithMessage("failed to generate prime pair")
	}
	// Sanity check on the generated primes: the lower bound makes the
	// modulus bit length exact by construction.
	if new(big.Int).Mul(pBig, qBig).BitLen() != int(keyLen) {
		return nilN, nilN, ErrFailed.WithMessage("internal: modulus does not have the requested bit length")
	}
	p, err = liftPrime(set, pBig)
	if err != nil {
		return nilN, nilN, err
	}
	q, err = liftPrime(set, qBig)
	if err != nil {
		return nilN, nilN, err
	}
	return p, q, nil
}

// fipsPairLowerBound returns ⌈√(2^(keyLen−1))⌉ = ⌈√2·2^(keyLen/2−1)⌉, the
// FIPS 186-5 A.1.1 2(b) lower bound on each prime of a keyLen-bit modulus:
// p ≥ this bound ⟺ p² ≥ 2^(keyLen−1) ⟺ bitlen(p²) ≥ keyLen.
func fipsPairLowerBound(keyLen uint) *big.Int {
	x := new(big.Int).Lsh(big.NewInt(1), keyLen-1)
	lo := new(big.Int).Sqrt(x) // ⌊√x⌋
	if new(big.Int).Mul(lo, lo).Cmp(x) < 0 {
		lo.Add(lo, big.NewInt(1))
	}
	return lo
}

// tinyPrime samples a prime below the sieve minimum via crypto/rand.Prime,
// double-checked with the FIPS-count Miller-Rabin rounds.
func tinyPrime(bits uint, prng io.Reader) (*big.Int, error) {
	checks := MillerRabinChecks(bits)
	for {
		p, err := crand.Prime(prng, int(bits))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("reading from crand")
		}
		if !p.ProbablyPrime(checks) {
			continue
		}
		return p, nil
	}
}

// generateTinyPrimePair handles prime pairs below the sieve minimum
// (keyLen/2 < 16 bits): rejection sampling over tinyPrime with the FIPS
// 186-5 A.1.1 checks that are meaningful at this size — the ⌈√2⌉ lower
// bound via the square's bit length and p ≠ q; the |p − q| distance
// condition is vacuous when keyLen/2 ≤ 100.
func generateTinyPrimePair[N algebra.NatPlusLike[N]](set PrimeSamplable[N], keyLen uint, prng io.Reader) (p, q N, err error) {
	var nilN N
	primeBits := keyLen / 2
	for {
		pBig, err := tinyPrime(primeBits, prng)
		if err != nil {
			return nilN, nilN, errs.Wrap(err).WithMessage("cannot generate prime")
		}
		qBig, err := tinyPrime(primeBits, prng)
		if err != nil {
			return nilN, nilN, errs.Wrap(err).WithMessage("cannot generate prime")
		}
		if pBig.Cmp(qBig) == 0 {
			continue
		}
		// FIPS 186-5 A.1.1 2(b): p² and q² at least keyLen bits ⟺ both
		// primes ≥ √2·2^(keyLen/2−1) ⟺ N = pq has exactly keyLen bits.
		if new(big.Int).Mul(pBig, pBig).BitLen() < int(keyLen) ||
			new(big.Int).Mul(qBig, qBig).BitLen() < int(keyLen) {

			continue
		}
		p, err = liftPrime(set, pBig)
		if err != nil {
			return nilN, nilN, err
		}
		q, err = liftPrime(set, qBig)
		if err != nil {
			return nilN, nilN, err
		}
		return p, q, nil
	}
}
