package nt

import (
	crand "crypto/rand"
	"crypto/rsa"
	"io"
	"maps"
	"math/big"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

// PrimeSamplable constrains the target structure a freshly sampled prime is
// lifted into. Sampling happens in big.Int and the result is converted via
// FromBig so the prime lands in a typed set (e.g. NatPlus) where downstream
// modular arithmetic is defined.
type PrimeSamplable[E algebra.NatPlusLike[E]] interface {
	FromBig(*big.Int) (E, error)
}

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
	p, err = set.FromBig(pBig)
	if err != nil {
		return *new(N), *new(N), errs.Wrap(err).WithMessage("cannot convert p to structure")
	}
	q, err = set.FromBig(qBig)
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
	four, err := num.NPlus().FromUint64(4)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("cannot create 4 in NPlus structure")
	}
	three := num.N().FromUint64(3)
	for {
		pBig, err := crand.Prime(prng, int(bits)-1)
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("reading from crand")
		}
		p, err := num.NPlus().FromBig(pBig)
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("cannot convert prime to NatPlus")
		}
		if !p.Mod(four).Nat().Equal(three) {
			continue
		}
		out, err := set.FromBig(p.Big())
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

// GeneratePaillierBlumModulus samples a Paillier-Blum modulus: N = pq where
// p, q are Blum primes (each ≡ 3 mod 4) and additionally gcd(N, φ(N)) = 1.
// The coprimality condition ensures (a) the map x ↦ x^N is a bijection on
// Z/N²Z*, which is exactly the soundness requirement underlying CGGMP21's
// Π^{mod} / Π^{fac} proofs that a committed modulus is a well-formed
// Paillier-Blum integer, and (b) that p-1 and q-1 do not share a common
// factor dividing N (in particular, neither p nor q divides (p-1)(q-1)).
func GeneratePaillierBlumModulus[E algebra.NatPlusLike[E]](set PrimeSamplable[E], keyLen uint, prng io.Reader) (N, p, q E, err error) {
	if set == nil {
		return *new(E), *new(E), *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if keyLen < 6 {
		return *new(E), *new(E), *new(E), ErrInvalidArgument.WithMessage("blum prime pair size must be at least 6-bits")
	}
	p, q, err = generatePrimePair(GenerateBlumPrime, set, keyLen, prng, func(p, q E) bool {
		N := p.Mul(q)
		NAsNatPlus, err := num.NPlus().FromCardinal(N.Cardinal())
		if err != nil {
			return false
		}
		pAsNatPlus, err := num.NPlus().FromCardinal(p.Cardinal())
		if err != nil {
			return false
		}
		qAsNatPlus, err := num.NPlus().FromCardinal(q.Cardinal())
		if err != nil {
			return false
		}
		phiN := pAsNatPlus.Lift().Decrement().Mul(qAsNatPlus.Lift().Decrement())
		return phiN.Abs().Coprime(NAsNatPlus.Nat())
	})
	if err != nil {
		return *new(E), *new(E), *new(E), errs.Wrap(err).WithMessage("failed to generate blum prime pair")
	}
	N = p.Mul(q)
	return N, p, q, nil

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
func GenerateSafePrime[E algebra.NatPlusLike[E]](set PrimeSamplable[E], bits uint, prng io.Reader) (E, error) {
	if set == nil {
		return *new(E), ErrIsNil.WithMessage("nil structure")
	}
	if bits < 3 {
		return *new(E), ErrInvalidArgument.WithMessage("safe prime size must be at least 3-bits")
	}
	checks := MillerRabinChecks(bits)
	for {
		pBig, err := crand.Prime(prng, int(bits)-1)
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("reading from crand")
		}
		p, err := num.NPlus().FromBig(pBig)
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("cannot convert prime to NatPlus")
		}
		p = p.Lsh(1).Add(num.NPlus().One())
		if !p.Big().ProbablyPrime(checks) {
			continue
		}
		out, err := set.FromBig(p.Big())
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("cannot convert prime to structure")
		}
		return out, nil
	}
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
	if keyLen < 6 {
		return *new(E), *new(E), ErrInvalidArgument.WithMessage("safe prime pair size must be at least 6-bits")
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
