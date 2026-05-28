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
	if bits < 3 {
		return *new(E), ErrInvalidArgument.WithMessage("blum prime size must be at least 3-bits")
	}
	checks := MillerRabinChecks(bits)
	numBytes := (bits + 7) / 8
	topBits := max(bits%8, 8)
	topByteMask := byte((1 << topBits) - 1)
	topByteMSB := byte(1) << (topBits - 1)
	buf := make([]byte, numBytes)
	for {
		if _, err := io.ReadFull(prng, buf); err != nil {
			return *new(E), errs.Wrap(err).WithMessage("failed to read random bytes")
		}
		buf[0] &= topByteMask   // clamp: no bits above position (bits-1)
		buf[0] |= topByteMSB    // force top bit → candidate has exactly `bits` bits
		buf[numBytes-1] |= 0b11 // force ≡ 3 (mod 4); also implies odd

		candidate := new(big.Int).SetBytes(buf)

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
	if keyLen < 6 {
		return *new(E), *new(E), ErrInvalidArgument.WithMessage("blum prime pair size must be at least 6-bits")
	}
	p, q, err = generatePrimePair(GenerateBlumPrime, set, keyLen, prng)
	if err != nil {
		return *new(E), *new(E), errs.Wrap(err).WithMessage("failed to generate blum prime pair")
	}
	return p, q, nil
}

// GenerateSafePrime samples a safe prime p of the requested bit length, i.e.
// p = 2p' + 1 with p' (the "Sophie Germain" prime) also prime. Safe primes
// are the building block for RSA moduli with a strong algebraic structure:
// when N = pq is a product of two safe primes, the subgroup of quadratic
// residues QR_N has prime order p'q' (no small factors), which makes the
// subgroup cyclic of prime order, rules out small-subgroup attacks, and
// makes a random QR overwhelmingly a generator. The CGGMP21 ring-Pedersen
// parameters (N̂, s, t) and the Π^{prm} soundness argument both rely on
// this structural guarantee.
//
// Implementation: every safe prime p > 7 satisfies p ≡ 11 (mod 12), equivalently
// the Sophie-Germain prime q = (p-1)/2 ≡ 5 (mod 6). Candidates are drawn
// directly from that residue class — skipping the two most common trial-division
// rejections (divisibility by 2 and 3) — and the primality checks on q and p
// are interleaved via a cheap BPSW pass first so a candidate where q is prime
// but p is composite (or vice versa) is rejected before paying the full
// Miller-Rabin iteration count on either side.
func GenerateSafePrime[E algebra.NatPlusLike[E]](set PrimeSamplable[E], bits uint, prng io.Reader) (E, error) {
	if set == nil {
		return *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if bits < 4 {
		return *new(E), ErrInvalidArgument.WithMessage("safe prime size must be at least 4-bits")
	}
	// Sample k uniformly so that q = 6k+5 lies in [2^(bits-2), 2^(bits-1)),
	// making p = 2q+1 fall in [2^(bits-1), 2^bits) — exactly `bits` bits.
	one := big.NewInt(1)
	five := big.NewInt(5)
	six := big.NewInt(6)
	lo := new(big.Int).Sub(new(big.Int).Lsh(one, bits-2), five)
	hi := new(big.Int).Sub(new(big.Int).Lsh(one, bits-1), five)
	kMin := new(big.Int).Add(new(big.Int).Sub(lo, one), six)
	kMin.Div(kMin, six)
	kMax := new(big.Int).Div(hi, six)
	rangeLen := new(big.Int).Add(new(big.Int).Sub(kMax, kMin), one)
	qChecks := MillerRabinChecks(bits - 1)
	pChecks := MillerRabinChecks(bits)

	workers := runtime.GOMAXPROCS(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)
	results := make(chan E, 1)
	defer close(results)

	for range workers {
		g.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					k, err := crand.Int(prng, rangeLen)
					if err != nil {
						return errs.Wrap(err).WithMessage("failed to sample random element")
					}
					k.Add(k, kMin)
					q := new(big.Int).Add(new(big.Int).Mul(k, six), five)
					p := new(big.Int).Add(new(big.Int).Lsh(q, 1), one)
					// Interleaved BPSW (trial division + 1 Miller-Rabin + Lucas) on each side
					// before paying the full Miller-Rabin iteration count.
					// This works because ~75% of composite candidates die after a single check.
					if !q.ProbablyPrime(0) || !p.ProbablyPrime(0) {
						continue
					}
					if !q.ProbablyPrime(qChecks) || !p.ProbablyPrime(pChecks) {
						continue
					}
					out, err := set.FromBytesBE(p.Bytes())
					if err != nil {
						return errs.Wrap(err).WithMessage("cannot convert prime to structure")
					}
					select {
					case <-ctx.Done():
					case results <- out:
						cancel()
					}
				}
			}
		})
	}
	// when channel is full, len(results) == cap(results).
	// This happens when a worker succeeds, but another one fails during crand.Int or FromBytesBE.
	// In this case, we'll ignore the error and return the successfully generated prime.
	if err := g.Wait(); err != nil && !errs.Is(err, context.Canceled) && len(results) != cap(results) {
		return *new(E), errs.Wrap(err).WithMessage("failed to generate safe prime")
	}
	return <-results, nil
}

// GenerateSafePrimeJoye implements the safe-prime generation algorithm of
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
func GenerateSafePrimeJoye[E algebra.NatPlusLike[E]](set PrimeSamplable[E], bits uint, prng io.Reader) (E, error) {
	if set == nil {
		return *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if bits < 128 {
		return *new(E), ErrInvalidArgument.WithMessage("safe prime size must be at least 128-bits for Joye/Paillier")
	}

	// ──────────────────────────────────────────────────────────────────────
	// Setup: bit-length-dependent constants (Π, m, m', l, u).
	// ──────────────────────────────────────────────────────────────────────
	// All five are derived from `bits` and cached across calls; see
	// joyepaillier.go (computeJoyeParams) for the full derivation and the
	// mapping to Section 2 / Section 4.2 of the paper.
	params, err := joyeParamsFor(bits)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("failed to derive Joye-Paillier parameters")
	}
	m := params.m
	u := params.u
	l := params.l
	mPrime := params.mPrime

	// ──────────────────────────────────────────────────────────────────────
	// Per-call constant a — Section 4.2, "the constant a is chosen in QR(m)".
	// ──────────────────────────────────────────────────────────────────────
	// We need a ∈ QR(m) AND a ≡ 1 (mod 4). Both are satisfied by sampling
	// a random odd α coprime to m and squaring:
	//   - α odd ⇒ α² ≡ 1 (mod 8) ⇒ a ≡ 1 (mod 4). ✓
	//   - α ∈ Z*_m ⇒ α² ∈ Z*_m, and α² is automatically in QR(m). ✓
	// We reject a = 1 (the orbit k_i = a^i · k_0 would be a fixed point —
	// every iteration would test the same q).
	var a *big.Int
	for {
		alpha, err := crand.Int(prng, m)
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("failed to sample α")
		}
		if alpha.Sign() == 0 || alpha.Bit(0) == 0 {
			continue // α = 0 or even — not in Z*_m (since 4 | m)
		}
		if new(big.Int).GCD(nil, nil, alpha, m).Cmp(one) != 0 {
			continue // α shares a factor with Π or the odd part of w
		}
		a = new(big.Int).Mul(alpha, alpha)
		a.Mod(a, m)
		if a.Cmp(one) == 0 {
			continue // degenerate: orbit would never move
		}
		break
	}

	// Miller-Rabin iteration counts (FIPS 186-derived): q has `bits` bits,
	// (q−1)/2 has `bits-1`.
	checks := MillerRabinChecks(bits)
	pChecks := MillerRabinChecks(bits - 1)

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

	for range workers {
		g.Go(func() error {
			// ───────────────────────────────────────────────────────
			// Step 1 (Figure 6): χ ←$ (Z/mZ)*.
			// ───────────────────────────────────────────────────────
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

			// ───────────────────────────────────────────────────────
			// Step 2 (Figure 6): k ← 4·u·χ² + 3m' (mod m).
			// ───────────────────────────────────────────────────────
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

			// ───────────────────────────────────────────────────────
			// Steps 3–4 (Figure 6): candidate construction, primality
			// tests, and recycling. The paper imposes no iteration
			// bound — the orbit of a in Z*_m is huge, and a safe prime
			// is overwhelmingly likely to lie in it.
			// ───────────────────────────────────────────────────────
			for {
				// Cooperative cancel: another worker may have already won.
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				// Step 3: q ← [(k − t) mod m] + t + l.
				// We use t = 0 (a valid choice — see Section 2 of the
				// paper, where t = bΠ for b ∈ [b_min, b_max], and
				// b_min = b_max = 0 is permitted). k is already in
				// [0, m) from Step 2, so:
				q := new(big.Int).Add(k, l)
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
					q.ProbablyPrime(checks) && qHalf.ProbablyPrime(pChecks) {
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
	if keyLen < 256 {
		return *new(E), *new(E), ErrInvalidArgument.WithMessage("safe prime pair size must be at least 256-bits")
	}
	p, q, err = generatePrimePair(GenerateSafePrime, set, keyLen, prng)
	if err != nil {
		return *new(E), *new(E), errs.Wrap(err).WithMessage("failed to generate safe prime pair")
	}
	return p, q, nil
}

func generatePrimePair[N algebra.NatPlusLike[N]](gen PrimeSampler[N], set PrimeSamplable[N], keyLen uint, prng io.Reader, predicates ...func(N, N) bool) (p, q N, err error) {
	var nilN N
	if gen == nil || set == nil || prng == nil {
		return nilN, nilN, ErrIsNil.WithMessage("gen/set/prng must not be nil")
	}
	for _, pred := range predicates {
		if pred == nil {
			return nilN, nilN, ErrIsNil.WithMessage("predicates must not contain nil")
		}
	}
	bits := keyLen / 2

	for {
		var pCandidate, qCandidate N
		g := errgroup.Group{}
		g.Go(func() error {
			var err error
			pCandidate, err = gen(set, bits, prng)
			if err != nil {
				return errs.Wrap(err).WithMessage("cannot generate prime")
			}
			return nil
		})
		g.Go(func() error {
			var err error
			qCandidate, err = gen(set, bits, prng)
			if err != nil {
				return errs.Wrap(err).WithMessage("cannot generate prime")
			}
			return nil
		})
		if err := g.Wait(); err != nil {
			return nilN, nilN, errs.Wrap(err).WithMessage("cannot generate primes")
		}
		if pCandidate.Equal(qCandidate) {
			continue
		}
		modulus, err := num.N().FromCardinal(pCandidate.Mul(qCandidate).Cardinal())
		if err != nil {
			return nilN, nilN, errs.Wrap(err).WithMessage("cannot compute modulus")
		}
		if modulus.AnnouncedLen() != int(keyLen) {
			continue
		}
		if len(predicates) == 0 || sliceutils.All(predicates, func(pred func(N, N) bool) bool { return pred(pCandidate, qCandidate) }) {
			return pCandidate, qCandidate, nil
		}
	}
}
