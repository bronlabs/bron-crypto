// params.go derives and caches the per-(class, bit-length) constants of the
// sieve: the CRT modulus and basis, the window bound, the residue-sampling
// thresholds, and the packed trial-division groups. Setup is fully
// deterministic — it consumes no PRNG output — so the cache can be shared
// freely across callers.
package primegen

import (
	"math"
	"math/big"
	"sync"

	"github.com/bronlabs/errs-go/errs"
)

// Class selects the structural constraints of the requested prime.
type Class uint8

const (
	// Plain requests an odd prime with no further structure.
	Plain Class = iota
	// Blum requests a prime ≡ 3 (mod 4).
	Blum
	// Safe requests a safe prime: q ≡ 3 (mod 4) with (q−1)/2 also prime.
	// Safe primes are in particular Blum primes.
	Safe

	numClasses
)

// MinBits is the smallest supported prime bit length: below it the sieve
// cap 2^(bits−11) admits no small primes worth constructing with. Callers
// with smaller requests need a different strategy (nt falls back to
// crypto/rand.Prime).
const MinBits = 16

// residueFloor is the smallest admissible residue modulo an odd sieve prime:
// every class forbids residue 0 (the candidate would be divisible), and Safe
// additionally forbids residue 1 (the sieve prime would divide (q−1)/2).
func (c Class) residueFloor() int64 {
	if c == Safe {
		return 2
	}
	return 1
}

// pow2Factor is the power of two folded into the CRT modulus m: Blum and
// Safe pin q ≡ 3 (mod 4), so m = 4Π; Plain only needs q odd, so m = 2Π.
func (c Class) pow2Factor() uint {
	if c == Plain {
		return 1
	}
	return 2
}

// tdGroup is one uint64-packed group of trial-division primes: prod is the
// product of the group's primes (< 2^64), so a single big-by-word reduction
// q mod prod yields every member's residue via cheap uint64 arithmetic.
type tdGroup struct {
	prod   *big.Int
	primes []uint64
}

// params is the cached per-(class, bits) setup output. All fields are
// immutable once computed and may be shared across goroutines.
type params struct {
	class      Class
	bits       uint
	floor      int64      // residue floor: 1 (Plain, Blum) or 2 (Safe)
	m          *big.Int   // CRT modulus: 2Π (Plain) or 4Π (Blum, Safe)
	basis      []*big.Int // basis[i] ≡ 1 (mod smallPrimes[i]), ≡ 0 (mod m/smallPrimes[i])
	offset     *big.Int   // ≡ 0 (mod Π); ≡ 1 (mod 2) for Plain, ≡ 3 (mod 4) for Blum/Safe
	bBound     uint64     // exclusive bound on the window index b; q = x + b·m, b ∈ [0, bBound)
	bThreshold uint64     // rejection cutoff for the 64-bit window draw: largest multiple of bBound, mod 2^64; 0 means every draw is accepted
	spans      []uint32   // spans[i] = smallPrimes[i] − floor: the number of admissible residues
	thresholds []uint32   // rejection cutoffs for the 32-bit residue draws: largest multiple of spans[i], mod 2^32; 0 means every draw is accepted
	nPi        int        // number of small odd primes folded into Π
	tdGroups   []tdGroup  // packed trial-division groups over table primes beyond Π (may be empty)
}

type paramsKey struct {
	bits  uint
	class Class
}

var (
	paramsCache   = map[paramsKey]*params{}
	paramsCacheMu sync.RWMutex
)

// paramsFor returns the cached setup parameters for the given class and bit
// length, computing them on first use.
func paramsFor(class Class, bits uint) (*params, error) {
	key := paramsKey{bits: bits, class: class}
	// double-checked locking pattern
	paramsCacheMu.RLock()
	if p, ok := paramsCache[key]; ok {
		paramsCacheMu.RUnlock()
		return p, nil
	}
	paramsCacheMu.RUnlock()

	paramsCacheMu.Lock()
	defer paramsCacheMu.Unlock()
	if p, ok := paramsCache[key]; ok {
		return p, nil
	}
	p, err := computeParams(class, bits)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute sieve parameters")
	}
	paramsCache[key] = p
	return p, nil
}

func computeParams(class Class, bits uint) (*params, error) {
	if class >= numClasses {
		return nil, ErrInvalidArgument.WithMessage("unknown prime class")
	}
	if bits < MinBits {
		return nil, ErrInvalidArgument.WithMessage("prime size below the sieve minimum")
	}

	one := big.NewInt(1)

	// ──────────────────────────────────────────────────────────────────────
	// (A) Pick Π — the longest prefix of small odd primes with Π ≤ 2^(bits−11).
	// ──────────────────────────────────────────────────────────────────────
	// The cap keeps m = 2Π or 4Π small enough that at least 2^9 windows tile
	// [0, 2^bits), so the exact-range rejection in the generator accepts a
	// constant fraction of draws, while still admitting nearly the full
	// small-prime prefix at cryptographic bit lengths (181 primes at 1536).
	target := new(big.Int).Lsh(one, bits-11)
	pi := big.NewInt(1)
	nPi := 0
	for _, p := range &smallPrimes { // &smallPrimes is to avoid copying the 16376 bytes (gocritic linter)
		next := new(big.Int).Mul(pi, big.NewInt(p))
		if next.Cmp(target) > 0 {
			break
		}
		pi = next
		nPi++
	}
	if nPi == 0 {
		return nil, ErrInvalidArgument.WithMessage("bits too small to admit any small-prime sieve")
	}

	m := new(big.Int).Lsh(pi, class.pow2Factor()) // 2Π or 4Π
	floor := class.residueFloor()

	// ──────────────────────────────────────────────────────────────────────
	// (B) CRT basis vectors and residue-sampling thresholds.
	// ──────────────────────────────────────────────────────────────────────
	// basis[i] = (m/p_i)·((m/p_i)⁻¹ mod p_i), the standard CRT basis: with
	// x = offset + Σ r_i·basis[i] (mod m) we get x ≡ r_i (mod p_i) for every
	// sieve prime, with the power-of-two residue contributed by offset alone.
	//
	// thresholds[i] is the rejection-sampling cutoff for drawing r_i uniform
	// in {floor, …, p_i−1}: a 32-bit draw v is accepted iff v is below the
	// largest multiple of spans[i] in [0, 2^32] (then r_i = floor +
	// (v mod spans[i]) is exactly uniform). That multiple mod 2^32 is
	// −(2^32 mod spans[i]); it wraps to 0 exactly when spans[i] | 2^32
	// (Fermat-prime spans like 2, 4, 16), meaning every draw is accepted.
	// A rejected draw abandons its candidate slot (see tryCandidate) —
	// per-draw rejection probability is < p_i/2^32 < 2^-17.
	basis := make([]*big.Int, nPi)
	spans := make([]uint32, nPi)
	thresholds := make([]uint32, nPi)
	for i := range nPi {
		p := big.NewInt(smallPrimes[i])
		mi := new(big.Int).Div(m, p) // exact: p_i | Π | m
		inv := new(big.Int).ModInverse(mi, p)
		if inv == nil {
			return nil, ErrFailed.WithMessage("internal: m/p_i not invertible mod p_i (impossible — sieve primes are distinct)")
		}
		mi.Mul(mi, inv)
		basis[i] = mi.Mod(mi, m)
		spans[i] = uint32(smallPrimes[i] - floor)
		thresholds[i] = -uint32((uint64(1) << 32) % uint64(spans[i]))
	}

	// ──────────────────────────────────────────────────────────────────────
	// (C) offset — the power-of-two CRT component.
	// ──────────────────────────────────────────────────────────────────────
	// offset ≡ 0 (mod Π) always, so it never disturbs the r_i residues.
	// Plain needs offset odd (q must be odd): Π itself is odd. Blum/Safe
	// need offset ≡ 3 (mod 4): Π is odd, so either Π or 3·Π < m qualifies.
	offset := new(big.Int).Set(pi)
	if class != Plain && new(big.Int).And(pi, big.NewInt(3)).Cmp(big.NewInt(3)) != 0 {
		offset.Mul(offset, big.NewInt(3))
	}

	// ──────────────────────────────────────────────────────────────────────
	// (D) bBound — the number of m-wide windows tiling [0, 2^bits).
	// ──────────────────────────────────────────────────────────────────────
	// bBound = ⌈2^bits / m⌉. Every integer q ∈ [0, bBound·m) decomposes
	// uniquely as q = x + b·m with x ∈ [0, m), b ∈ [0, bBound); sampling x
	// uniform over the admissible residue set and b uniform over [0, bBound),
	// then rejecting q outside the target range, therefore yields an exactly
	// uniform sample from the admissible set intersected with the range.
	//
	// bBound always fits a uint64: extending Π by the next small prime
	// (< 2^15) would exceed the 2^(bits−11) cap, so Π > 2^(bits−26) and
	// bBound < 2^bits/(2·Π) + 1 < 2^25 — unless the smallPrimes table was
	// exhausted, which the IsUint64 check below catches defensively.
	bBoundBig := new(big.Int).Lsh(one, bits)
	bBoundBig.Add(bBoundBig, m)
	bBoundBig.Sub(bBoundBig, one)
	bBoundBig.Div(bBoundBig, m)
	if !bBoundBig.IsUint64() {
		return nil, ErrFailed.WithMessage("internal: bBound overflows uint64")
	}
	bBound := bBoundBig.Uint64()
	// b is drawn as a uniform 64-bit value v, accepted iff v is below the
	// largest multiple of bBound that fits in [0, 2^64] (then v mod bBound
	// is exactly uniform). That multiple is 2^64 − (2^64 mod bBound), which
	// modulo 2^64 is −(2^64 mod bBound); it wraps to 0 exactly when
	// bBound | 2^64, in which case every draw is accepted.
	bThreshold := -((-bBound) % bBound)

	// ──────────────────────────────────────────────────────────────────────
	// (E) Trial-division groups over the table primes beyond Π.
	// ──────────────────────────────────────────────────────────────────────
	// Primes that don't fit into the CRT modulus still pay for themselves as
	// trial divisors — but only up to a cutoff: rejecting with prime p saves
	// ~(2/p)·T_BPSW of expected testing time and costs a fixed ~tens of
	// nanoseconds, and T_BPSW shrinks roughly cubically with the bit length.
	// bits³/2^16 scales the break-even point accordingly: the whole table at
	// ≥ 1536 bits, ~2048 at 512 bits, none below ~192 bits.
	tdLimit := int64(bits) * int64(bits) * int64(bits) / 65536
	var tdGroups []tdGroup
	var cur []uint64
	prod := uint64(1)
	for _, p := range smallPrimes[nPi:] {
		if p > tdLimit {
			break
		}
		up := uint64(p)
		if prod > math.MaxUint64/up {
			tdGroups = append(tdGroups, tdGroup{prod: new(big.Int).SetUint64(prod), primes: cur})
			cur = nil
			prod = 1
		}
		prod *= up
		cur = append(cur, up)
	}
	if len(cur) > 0 {
		tdGroups = append(tdGroups, tdGroup{prod: new(big.Int).SetUint64(prod), primes: cur})
	}

	return &params{
		class:      class,
		bits:       bits,
		floor:      floor,
		m:          m,
		basis:      basis,
		offset:     offset,
		bBound:     bBound,
		bThreshold: bThreshold,
		spans:      spans,
		thresholds: thresholds,
		nPi:        nPi,
		tdGroups:   tdGroups,
	}, nil
}
