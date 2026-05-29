package nt

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"io"
	"maps"
	"math/big"
	"runtime"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
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

// GeneratePrime samples a single uniformly random prime of the requested bit
// length. It is implemented by discarding one half of a fresh RSA-style
// prime pair so that callers pay the same high-entropy generation cost and
// receive a prime drawn from the same distribution used by GeneratePrimePair.
func GeneratePrime[E algebra.NatPlusLike[E]](set PrimeSamplable[E], bits uint, prng io.Reader) (E, error) {
	// https://pkg.go.dev/crypto/rsa#hdr-Minimum_key_size
	if bits < 512 {
		checks := MillerRabinChecks(bits)
		for {
			pBig, err := crand.Prime(prng, int(bits))
			if err != nil {
				return *new(E), errs.Wrap(err).WithMessage("reading from crand")
			}
			if !pBig.ProbablyPrime(checks) {
				continue
			}
			out, err := set.FromBytesBE(pBig.Bytes())
			if err != nil {
				return *new(E), errs.Wrap(err).WithMessage("cannot convert prime to structure")
			}
			return out, nil
		}
	}
	// generating a prime pair via rsa.GenerateKey and discarding one of them, is less expensive than
	// calling crand.Prime(bits) directly.
	p, _, err := GeneratePrimePair(set, bits*2, prng)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("failed to generate prime pair")
	}
	return p, nil
}

// GeneratePrimePair samples an RSA-style prime pair (p, q) whose product has
// bit length keyLen. Each prime has bit length keyLen/2 and is drawn via
// crypto/rsa.GenerateKey, so the returned primes inherit the standard RSA
// generation distribution (distinct, of equal length, and large enough that
// neither side is susceptible to trivial factoring). The function enforces
// that both primes have the requested bit length; no further structural
// constraint (such as p ≡ 3 mod 4 or (p-1)/2 prime) is imposed.
func GeneratePrimePair[N algebra.NatPlusLike[N]](set PrimeSamplable[N], keyLen uint, prng io.Reader) (p, q N, err error) {
	if set == nil {
		return *new(N), *new(N), ErrIsNil.WithMessage("nil structure")
	}
	// https://pkg.go.dev/crypto/rsa#hdr-Minimum_key_size
	if keyLen < 1024 {
		p, q, err = generatePrimePair(GeneratePrime, set, keyLen, prng)
		if err != nil {
			return *new(N), *new(N), errs.Wrap(err).WithMessage("failed to generate prime pair")
		}
		return p, q, nil
	}

	rsaPrivateKey, err := rsa.GenerateKey(prng, int(keyLen))
	if err != nil {
		return *new(N), *new(N), errs.Wrap(err).WithMessage("cannot generate keys pair")
	}
	pBig := rsaPrivateKey.Primes[0]
	qBig := rsaPrivateKey.Primes[1]
	// double check
	if pBig.BitLen() != int(keyLen/2) || qBig.BitLen() != int(keyLen/2) {
		return *new(N), *new(N), errs.New("p,q have invalid length (%d, %d) - expected %d", pBig.BitLen(), qBig.BitLen(), keyLen)
	}
	p, err = set.FromBytesBE(pBig.Bytes())
	if err != nil {
		return *new(N), *new(N), errs.Wrap(err).WithMessage("cannot convert p to structure")
	}
	q, err = set.FromBytesBE(qBig.Bytes())
	if err != nil {
		return *new(N), *new(N), errs.Wrap(err).WithMessage("cannot convert q to structure")
	}
	return p, q, nil
}

// GenerateBlumPrime samples a prime p of the requested bit length with
// p ≡ 3 (mod 4) (a "Blum" prime). In Z/pZ with p ≡ 3 mod 4, -1 is a
// quadratic non-residue, so exactly one of {x, -x} is a quadratic residue
// for every x ∈ Z/pZ*. Products of two Blum primes form Blum integers,
// on which ZK arguments such as CGGMP21's Π^{mod} rely.
func GenerateBlumPrime[E algebra.NatPlusLike[E]](set PrimeSamplable[E], bits uint, prng io.Reader) (E, error) {
	if set == nil {
		return *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if bits < 16 {
		return *new(E), ErrInvalidArgument.WithMessage("blum prime size must be at least 16-bits")
	}
	params, err := joyeParamsFor(bits, prng)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("failed to get Joye-Paillier parameters")
	}
	checks := MillerRabinChecks(bits)
	numBytes := (bits + 7) / 8
	topBits := max(bits%8, 8)
	topByteMask := byte((1 << topBits) - 1)
	topByteMSB := byte(1) << (topBits - 1)
	buf := make([]byte, numBytes)

	candidate := new(big.Int)
	residue := new(big.Int)

OUTER:
	for {
		if _, err := io.ReadFull(prng, buf); err != nil {
			return *new(E), errs.Wrap(err).WithMessage("failed to read random bytes")
		}
		buf[0] &= topByteMask   // clamp: no bits above position (bits-1)
		buf[0] |= topByteMSB    // force top bit → candidate has exactly `bits` bits
		buf[numBytes-1] |= 0b11 // force ≡ 3 (mod 4); also implies odd

		candidate.SetBytes(buf)
		residue.Mod(candidate, params.pi)
		tmp := new(big.Int)
		for _, p := range (&smallPrimes)[:params.nPi] { // &smallPrimes is to avoid copying the 16376 bytes (gocritic linter)
			if tmp.Mod(residue, big.NewInt(p)).Sign() == 0 {
				continue OUTER
			}
		}
		if !candidate.ProbablyPrime(checks) {
			continue
		}
		out, err := set.FromBytesBE(buf)
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("cannot convert prime to structure")
		}
		return out, nil
	}
}

// GenerateBlumPrimePair samples a pair of Blum primes (each ≡ 3 mod 4) of
// half the given keyLen each, whose product N = pq is a Blum integer of
// bit length keyLen. Blum integers enjoy the key property that squaring
// is a 4-to-1 map on Z/NZ* whose image is precisely QR_N, giving QR_N a
// canonical set of representatives — used both by Paillier-Blum ZK proofs
// and by Rabin-style commitments.
func GenerateBlumPrimePair[E algebra.NatPlusLike[E]](set PrimeSamplable[E], keyLen uint, prng io.Reader) (p, q E, err error) {
	if set == nil {
		return *new(E), *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if keyLen < 32 {
		return *new(E), *new(E), ErrInvalidArgument.WithMessage("blum prime pair size must be at least 32-bits")
	}
	p, q, err = generatePrimePair(GenerateBlumPrime, set, keyLen, prng)
	if err != nil {
		return *new(E), *new(E), errs.Wrap(err).WithMessage("failed to generate blum prime pair")
	}
	return p, q, nil
}

// GenerateSafePrime implements the safe-prime generation algorithm of
// Joye and Paillier, "Fast Generation of Prime Numbers on Portable Devices:
// An Update" (CHES 2006), Figure 6. The implementation here is a parallel
// adaptation: GOMAXPROCS workers each draw an independent χ and walk
// independent recycling orbits; the first worker to produce a safe prime
// wins and the rest are cancelled.
//
// Algorithmic core (per Section 4.2 of the paper). Candidates have the form
//
//	q = (k mod m) + l        with k = 4·u·χ² + 3m' (mod m) initially,
//	                              k ← a·k (mod m) after each rejection.
//
// Three structural invariants on q hold for every iteration:
//
//  1. q is coprime to Π. Reason: k ≡ a^j · u · χ² (mod Π); a ∈ QR(m) and χ²
//     is a square, so q mod p_i ≡ (QR)·(QR)·u (mod p_i) is a QNR — in
//     particular ≢ 0 (mod p_i). And l = v·Π contributes 0 mod p_i.
//
//  2. (q−1)/2 is coprime to Π. From (1) q is a QNR mod every odd p_i | Π,
//     hence q ≢ 1 (mod p_i), hence p_i ∤ (q−1), hence p_i ∤ (q−1)/2.
//
//  3. (q−1)/2 is odd. From the construction, k ≡ 3 (mod 4) initially
//     (4uχ² ≡ 0; 3m' ≡ 3 because m' ≡ 1 mod 4 by setup). The recycling
//     k ← a·k preserves this because a ≡ 1 (mod 4). l ≡ 0 (mod 4) by
//     setup. So q ≡ 3 (mod 4) and (q−1)/2 is odd.
//
// Together (1)–(3) guarantee both q and (q−1)/2 are coprime to 2Π by
// construction — no per-candidate trial division is needed. Expected
// primality-test count is ≈ (n · ln 2 · φ(Π)/Π)² for an n-bit safe prime.
//
// IMPORTANT: prng must be safe for concurrent use (e.g. crypto/rand.Reader).
// Workers call crand.Int(prng, …) concurrently — a single-threaded PRNG
// like *pcg.Pcg will race.
func GenerateSafePrime[E algebra.NatPlusLike[E]](set PrimeSamplable[E], bits uint, prng io.Reader) (E, error) {
	if set == nil {
		return *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if prng == nil {
		return *new(E), ErrIsNil.WithMessage("nil prng")
	}
	if bits < 16 {
		return *new(E), ErrInvalidArgument.WithMessage("safe prime size must be at least 16-bits for Joye/Paillier")
	}

	// ──────────────────────────────────────────────────────────────────────
	// Setup: bit-length-dependent constants (Π, m, m', l, u).
	// ──────────────────────────────────────────────────────────────────────
	// All five are derived from `bits` and cached across calls; see
	// joyepaillier.go (computeJoyeParams) for the full derivation and the
	// mapping to Section 2 / Section 4.2 of the paper.
	params, err := joyeParamsFor(bits, prng)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("failed to derive Joye-Paillier parameters")
	}
	m := params.m
	u := params.u
	l := params.l
	mPrime := params.mPrime
	a := params.a
	pi := params.pi
	bMaxPlusOne := new(big.Int).SetUint64(params.bMax + 1)

	// Miller-Rabin iteration counts (FIPS 186-derived): q has `bits` bits,
	// (q−1)/2 has `bits-1`.
	checks := MillerRabinChecks(bits)
	halfChecks := MillerRabinChecks(bits - 1)

	// 3·m' — additive constant used in Step 2 of Figure 6. Precomputed
	// because it's identical for every worker and every χ.
	threeMPrime := new(big.Int).Mul(three, mPrime)

	// ──────────────────────────────────────────────────────────────────────
	// Parallel scaffolding.
	// ──────────────────────────────────────────────────────────────────────
	// One worker per CPU. Each runs an independent (χ, orbit) per Fig. 6.
	// First worker to find a safe prime wins; cancel() stops the rest.
	workers := runtime.GOMAXPROCS(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)
	results := make(chan E, 1)
	defer close(results)

	// Bound on the orbit walk per χ sample. Joye–Paillier (Section 4.2,
	// "A note on efficiency") gives the expected number of primality tests
	// for an n-bit safe prime as ≈ (n · ln 2 · φ(Π)/Π)². The paper's
	// distribution analysis (Section 3.1, Theorem 1) is stated for n ≥ 256,
	// at which point ord(a) ≤ λ(m) is huge and the expected count is
	// orders of magnitude below this bound — so the bound is essentially
	// never hit on cryptographic-sized inputs.
	//
	// For small n exercised by tests, however, the orbit is small enough
	// that it may contain *no* safe prime at all (e.g. bits = 16 gives
	// λ(m) ≤ 60). When the bound trips we drop back to the outer loop and
	// resample χ, putting the worker into a different coset of ⟨a⟩.
	const maxOrbitIter = 1 << 16

	for range workers {
		g.Go(func() error {
			// Outer loop: keep drawing fresh χ until one yields a safe prime
			// within maxOrbitIter recyclings, or until ctx is cancelled.
			for {
				// Cooperative cancel at the χ-resample boundary.
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				// ───────────────────────────────────────────────
				// Step 1 (Figure 6): χ ←$ (Z/mZ)*.
				// ───────────────────────────────────────────────
				// Rejection sampling: draw uniformly from [0, m) and accept
				// when the sample is a unit. Acceptance rate is φ(m)/m,
				// dominated by φ(Π)/Π in our setup (≈ 0.16 for nPi ≈ 175).
				var chi *big.Int
				for {
					c, err := crand.Int(prng, m)
					if err != nil {
						return errs.Wrap(err).WithMessage("failed to sample χ")
					}
					if c.Sign() == 0 {
						continue
					}
					if new(big.Int).GCD(nil, nil, c, m).Cmp(one) != 0 {
						continue
					}
					chi = c
					break
				}

				// ───────────────────────────────────────────────
				// Step 2 (Figure 6): k ← 4·u·χ² + 3m' (mod m).
				// ───────────────────────────────────────────────
				// Residue analysis of the resulting k:
				//   • mod p_i (odd, p_i | Π):
				//       4·u·χ² ≡ 4·(QNR)·(QR) ≡ QNR (mod p_i)  [4 is a QR mod any odd p]
				//       3m'    ≡ 0           (since p_i | m and 4 | m, p_i | m', so p_i | 3m')
				//     ⇒ k ≡ QNR (mod p_i) — the property that makes (q−1)/2
				//       automatically coprime to Π.
				//   • mod 4:
				//       4·u·χ² ≡ 0
				//       3m'    ≡ 3·1 = 3   (m' ≡ 1 mod 4 by setup)
				//     ⇒ k ≡ 3 (mod 4) — the property that makes q ≡ 3 (mod 4)
				//       once we add l ≡ 0 (mod 4) in Step 3.
				k := new(big.Int).Mul(chi, chi)
				k.Mul(k, u)
				k.Lsh(k, 2) // ×4
				k.Add(k, threeMPrime)
				k.Mod(k, m)

				// ───────────────────────────────────────────────
				// Random-b shift (§2.1): t ← b·Π, b ←$ [0, bMax].
				// ───────────────────────────────────────────────
				// §2.1 introduces a per-call random b ∈ {b_min, …, b_max}
				// with t = b·Π. The union of all per-call output windows
				// then covers ≈ (1 − ε) of [q_min, q_max], where ε is §2's
				// quality parameter ("a typical value is 10⁻³").
				//
				// Derivation of ε. The coverage of [q_min, q_max] under the
				// random-b scheme is
				//
				//   Coverage = (w + bMax)·Π.
				//
				// bMax = ⌊(2^bits − l − m) / Π⌋, so writing the floor
				// remainder as r ∈ [0, Π) we get bMax·Π = 2^bits − l − m − r,
				// hence
				//
				//   Coverage = m + bMax·Π = 2^bits − l − r.
				//
				// l overshoots q_min = 2^(bits-1) by δ_l ∈ [0, 4·Π) (v is
				// rounded up to the next multiple of 4 in setup step (C);
				// see joyepaillier.go). So writing l = 2^(bits-1) + δ_l:
				//
				//   ε = 1 − Coverage/(q_max − q_min)
				//     = (δ_l + r) / 2^(bits-1)
				//     < 5·Π / 2^(bits-1).
				//
				// Setup picks Π as the longest smallPrimes-prefix with
				// Π ≤ 2^(bits−11). For large enough bits the prefix can
				// pack close to the cap, so Π ≈ 2^(bits−11) and
				//
				//   ε ≲ 5 · 2^(bits−11) / 2^(bits-1) = 5·2⁻¹⁰ ≈ 5·10⁻³,
				//
				// in the order of magnitude of the paper's recommended 10⁻³.
				// At very small bits the prefix can't fill the cap; Π and
				// ε both shrink correspondingly.
				//
				// b is fixed for the entire recycling orbit below — same
				// scoping as Fig. 3 of §2.1.
				bRand, err := crand.Int(prng, bMaxPlusOne)
				if err != nil {
					return errs.Wrap(err).WithMessage("failed to sample b")
				}
				// t MUST be sampled per call (per outer χ-resample here),
				// NOT precomputed once at setup. Setup-fixed t would pin
				// every safe prime from this process into the same single
				// m-wide window of size ≈ wResidue·Π ≈ 12·2^(bits−11), which
				// is only ≈ 12·2⁻¹⁰ ≈ 1.2% of [q_min, q_max] — dropping ~10
				// bits of position entropy and giving every output modulus
				// an observable upper-bit fingerprint. §2.1's prose ("t
				// varying as a random multiple of Π, instead of fixing it")
				// and its modified (P1) numerator (b_max − b_min + 1)·Π
				// both require per-call b for the algorithm's coverage
				// analysis to hold.
				t := new(big.Int).Mul(bRand, pi)

				// ───────────────────────────────────────────────
				// Steps 3–4 (Figure 6): candidate construction,
				// primality tests, and recycling — bounded to
				// maxOrbitIter for the small-bits liveness reason
				// noted above. On bound-hit we fall through to the
				// outer loop and resample (χ, b).
				// ───────────────────────────────────────────────
				for range maxOrbitIter {
					// Cooperative cancel: another worker may have already won.
					select {
					case <-ctx.Done():
						return ctx.Err()
					default:
					}

					// Step 3: q ← [(k − t) mod m] + t + l.
					// Writing it in the paper's form (rather than the
					// equivalent k + t + l) keeps q mod 4 independent of t:
					//   ((k − t) mod m + t + l) mod 4 = (k + l) mod 4
					// since 4 | m. With k ≡ 3 (mod 4) and l ≡ 0 (mod 4),
					// q ≡ 3 (mod 4) for every b — no constraint on b's
					// residue needed.
					q := new(big.Int).Sub(k, t)
					q.Mod(q, m)
					q.Add(q, t)
					q.Add(q, l)
					// (q − 1)/2: the Sophie-Germain half. Odd by invariant (3).
					qHalf := new(big.Int).Rsh(new(big.Int).Sub(q, one), 1)

					// Step 4: T(q) and T((q−1)/2). The paper specifies an
					// abstract primality test T — we use a two-stage:
					//   (i)  ProbablyPrime(0) = BPSW (trial division on a
					//        fixed small-prime list + base-2 Miller-Rabin +
					//        Lucas test). Cheapest reliable filter.
					//   (ii) ProbablyPrime(N) for the FIPS-derived count N,
					//        for the formal 4^{-N} soundness bound.
					if q.ProbablyPrime(0) && qHalf.ProbablyPrime(0) &&
						q.ProbablyPrime(checks) && qHalf.ProbablyPrime(halfChecks) {
						// Step 5 (Figure 6): output q.
						out, err := set.FromBytesBE(q.Bytes())
						if err != nil {
							return errs.Wrap(err).WithMessage("cannot convert prime to structure")
						}
						// Race-safe single-result delivery.
						select {
						case <-ctx.Done():
						case results <- out:
							cancel()
						}
						return nil
					}

					// Step 4(a): k ← a·k (mod m).
					// Step 4(b): jump to Step 3 (top of this for-loop).
					//
					// Why this preserves the invariants:
					//   • mod p_i: a ∈ QR(p_i), so multiplying preserves the
					//     QNR-ness of k mod p_i.
					//   • mod 4: a ≡ 1 (mod 4), so k stays ≡ 3 (mod 4).
					k.Mul(k, a)
					k.Mod(k, m)
				}
				// Bound hit — orbit of this χ did not yield a safe prime.
				// Fall through to the outer loop to draw a fresh χ.
			}
		})
	}

	// On success, the winning worker fills the cap-1 results channel and
	// cancels the context; every worker (including the winner) then
	// returns context.Canceled via the cooperative-cancel select. The
	// salvage clause `len(results) != cap(results)` rescues a successful
	// generation even if another worker happened to err in parallel.
	if err := g.Wait(); err != nil && !errs.Is(err, context.Canceled) && len(results) != cap(results) {
		return *new(E), errs.Wrap(err).WithMessage("failed to generate safe prime")
	}
	return <-results, nil
}

// GenerateSafePrimePair samples two independent safe primes p, q of half the
// given keyLen each. The resulting modulus N = pq is used wherever a strong
// RSA modulus is required: ring-Pedersen commitments, proofs over QR_N with
// prime-order structure, and range proofs that rely on the discrete log
// assumption in QR_N being hard.
func GenerateSafePrimePair[E algebra.NatPlusLike[E]](set PrimeSamplable[E], keyLen uint, prng io.Reader) (p, q E, err error) {
	if set == nil {
		return *new(E), *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if keyLen < 32 {
		return *new(E), *new(E), ErrInvalidArgument.WithMessage("safe prime pair size must be at least 32-bits")
	}
	p, q, err = generatePrimePair(GenerateSafePrime, set, keyLen, prng)
	if err != nil {
		return *new(E), *new(E), errs.Wrap(err).WithMessage("failed to generate safe prime pair")
	}
	return p, q, nil
}

// generatePrimePair generates two primes p, q whose bitlen is keyLen/2 and whose product is keyLen bits.
// The primes satisfy IFC Key generation requirements of FIPS 186-5 A.1.1.
func generatePrimePair[N algebra.NatPlusLike[N]](gen PrimeSampler[N], set PrimeSamplable[N], keyLen uint, prng io.Reader, predicates ...func(N, N) bool) (p, q N, err error) {
	var nilN N
	if gen == nil || set == nil || prng == nil {
		return nilN, nilN, ErrIsNil.WithMessage("gen/set/prng must not be nil")
	}
	if keyLen%2 != 0 {
		return nilN, nilN, ErrInvalidArgument.WithMessage("keyLen must be even")
	}
	for _, pred := range predicates {
		if pred == nil {
			return nilN, nilN, ErrIsNil.WithMessage("predicates must not contain nil")
		}
	}
	primeBits := keyLen / 2

	for {
		var pCandidate, qCandidate N
		var pCandidateNat, qCandidateNat *num.NatPlus
		g := errgroup.Group{}
		// We need to check FIPS 186-5 A.1.1 2(b) and 2(c). ie.
		// sqrt(2)(2^(keyLen/2 - 1)) <= p, q <= 2^(keyLen/2) - 1
		// The upper bound is guaranteed by the bit length of the generated primes, but the lower bound is not.
		// So we loop until we get candidates that satisfy the lower bound, and then check the predicates on those candidates.
		// To avoid doing a sqrt, we square and do log2.
		// sqrt(2)(2^(keyLen/2 - 1)) <= p, q  ==>
		// 2^(keyLen - 1) <= p^2, q^2
		g.Go(func() error {
			var err error
			for {
				pCandidate, err = gen(set, primeBits, prng)
				if err != nil {
					return errs.Wrap(err).WithMessage("cannot generate prime")
				}
				pCandidateNat, err = num.NPlus().FromCardinal(pCandidate.Cardinal())
				if err != nil {
					return errs.Wrap(err).WithMessage("cannot convert p to NatPlus")
				}
				if pCandidateNat.Square().TrueLen() >= int(keyLen) { // TrueLen()/BitLen() gives the index of the highest set bit plus one, so it's int(keyLen) not int(keyLen-1)
					return nil
				}
			}
		})
		g.Go(func() error {
			var err error
			for {
				qCandidate, err = gen(set, primeBits, prng)
				if err != nil {
					return errs.Wrap(err).WithMessage("cannot generate prime")
				}
				qCandidateNat, err = num.NPlus().FromCardinal(qCandidate.Cardinal())
				if err != nil {
					return errs.Wrap(err).WithMessage("cannot convert q to NatPlus")
				}
				if qCandidateNat.Square().TrueLen() >= int(keyLen) {
					return nil
				}
			}
		})
		if err := g.Wait(); err != nil {
			return nilN, nilN, errs.Wrap(err).WithMessage("cannot generate primes")
		}
		if pCandidate.Equal(qCandidate) {
			continue
		}
		// ensuring the modulus has the correct bit length is a sanity check on the generated primes.
		if pCandidateNat.Mul(qCandidateNat).TrueLen() != int(keyLen) {
			continue
		}

		// We need to check FIPS 186-5 A.1.1 2(d) to prevent against Fermat factorization should the generated primes be too close.
		// |p - q| > 2^(keyLen/2 - 100)
		// Note that if keyLen/2 <= 100, then the distance bound is vacuous since p != q already implies |p-q| >= 2, so we only check the distance when keyLen/2 > 100.
		if pCandidateNat.Lift().Sub(qCandidateNat.Lift()).Abs().TrueLen() <= int(primeBits)-100 {
			continue
		}

		if len(predicates) == 0 || sliceutils.All(predicates, func(pred func(N, N) bool) bool { return pred(pCandidate, qCandidate) }) {
			return pCandidate, qCandidate, nil
		}
	}
}
