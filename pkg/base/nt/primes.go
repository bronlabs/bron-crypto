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

// PrimeSamplable is an interface for types that can sample prime numbers.
type PrimeSamplable[E algebra.NatPlusLike[E]] interface {
	FromBig(*big.Int) (E, error)
}

// MillerRabinChecks returns the number of Miller-Rabin iterations required for a given bit length.
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

// NewPrimeGenerator creates a PrimeGenerator that samples primes from the given structure.
// If isSafe is true, generated primes p satisfy that (p-1)/2 is also prime.
// If isBlum is true, generated primes satisfy p ≡ 3 (mod 4).
func NewPrimeGenerator[E algebra.NatPlusLike[E]](set PrimeSamplable[E], isSafe, isBlum bool) (*PrimeGenerator[E], error) {
	if set == nil {
		return nil, ErrIsNil.WithMessage("nil structure")
	}
	return &PrimeGenerator[E]{
		set:    set,
		isSafe: isSafe,
		isBlum: isBlum,
	}, nil
}

// PrimeGenerator samples primes of a specified bit length, optionally constrained to safe and/or Blum primes.
type PrimeGenerator[E algebra.NatPlusLike[E]] struct {
	set    PrimeSamplable[E]
	isSafe bool
	isBlum bool
}

// Generate returns a prime of the given bit length sampled from the configured structure,
// subject to the generator's safe and/or Blum constraints.
func (g *PrimeGenerator[E]) Generate(bits uint, prng io.Reader) (E, error) {
	if bits < 3 {
		return *new(E), ErrInvalidArgument.WithMessage("safe prime size must be at least 3-bits")
	}
	if prng == nil {
		return *new(E), ErrIsNil.WithMessage("nil prng")
	}
	if !g.isSafe && !g.isBlum {
		p, _, err := generateRegularPrimePair(g.set, bits, prng)
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("failed to generate regular prime pair")
		}
		return p, nil
	}

	four, err := num.NPlus().FromUint64(4)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("cannot create 4 in NPlus structure")
	}
	three := num.N().FromUint64(3)

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
		if g.isSafe {
			p = p.Lsh(1).Add(num.NPlus().One())
			if !p.Big().ProbablyPrime(checks) {
				continue
			}
		}
		if g.isBlum {
			if !p.Mod(four).Nat().Equal(three) {
				continue
			}
		}
		out, err := g.set.FromBig(p.Big())
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("cannot convert prime to structure")
		}
		return out, nil
	}
}

// NewPrimePairGenerator creates a PrimePairGenerator that samples distinct prime pairs (p, q) from the given structure.
// If isSafe is true, both primes are safe primes.
// If isPaillierBlum is true, both primes are Blum primes (≡ 3 mod 4) and the resulting modulus N = p*q has the full
// requested bit length with gcd(φ(N), N) = 1.
func NewPrimePairGenerator[E algebra.NatPlusLike[E]](set PrimeSamplable[E], isSafe, isPaillierBlum bool) (*PrimePairGenerator[E], error) {
	if set == nil {
		return nil, ErrIsNil.WithMessage("nil structure")
	}
	return &PrimePairGenerator[E]{
		set:            set,
		isSafe:         isSafe,
		isPaillierBlum: isPaillierBlum,
	}, nil
}

// PrimePairGenerator samples a pair of distinct primes (p, q) whose product has a specified bit length,
// optionally constrained to safe primes and/or a Paillier-Blum modulus.
type PrimePairGenerator[E algebra.NatPlusLike[E]] struct {
	set            PrimeSamplable[E]
	isSafe         bool
	isPaillierBlum bool
}

// Generate returns a pair of distinct primes (p, q) such that N = p*q has exactly the given keyLen bit length,
// subject to the generator's safe and/or Paillier-Blum constraints.
func (g *PrimePairGenerator[E]) Generate(keyLen uint, prng io.Reader) (p, q E, err error) {
	bits := keyLen / 2
	if bits < 3 {
		return *new(E), *new(E), ErrInvalidArgument.WithMessage("safe prime size must be at least 3-bits")
	}
	if prng == nil {
		return *new(E), *new(E), ErrIsNil.WithMessage("nil prng")
	}

	if !g.isSafe && !g.isPaillierBlum {
		p, q, err := generateRegularPrimePair(g.set, bits, prng)
		if err != nil {
			return *new(E), *new(E), errs.Wrap(err).WithMessage("failed to generate regular prime pair")
		}
		return p, q, nil
	}
	pgen, err := NewPrimeGenerator(g.set, g.isSafe, g.isPaillierBlum)
	if err != nil {
		return *new(E), *new(E), errs.Wrap(err).WithMessage("failed to create prime generator")
	}
	for {
		p, q, err := generatePrimePair(pgen, keyLen, prng)
		if err != nil {
			return *new(E), *new(E), errs.Wrap(err).WithMessage("failed to generate prime pair")
		}
		if g.isPaillierBlum {
			N := p.Mul(q)
			NAsNatPlus, err := num.NPlus().FromCardinal(N.Cardinal())
			if err != nil {
				return *new(N), *new(N), errs.Wrap(err).WithMessage("failed to convert N to NatPlus")
			}
			if NAsNatPlus.AnnouncedLen() != int(keyLen) {
				continue
			}
			pAsNatPlus, err := num.NPlus().FromCardinal(p.Cardinal())
			if err != nil {
				return *new(N), *new(N), errs.Wrap(err).WithMessage("failed to convert p to NatPlus")
			}
			qAsNatPlus, err := num.NPlus().FromCardinal(q.Cardinal())
			if err != nil {
				return *new(N), *new(N), errs.Wrap(err).WithMessage("failed to convert q to NatPlus")
			}
			phiN := pAsNatPlus.Lift().Decrement().Mul(qAsNatPlus.Lift().Decrement())

			if !phiN.Abs().Coprime(NAsNatPlus.Nat()) {
				continue
			}
		}
		return p, q, nil
	}
}

// generateRegularPrimePair produces a distinct prime pair (p, q) each of the requested bit length by delegating to crypto/rsa.
func generateRegularPrimePair[N algebra.NatPlusLike[N]](set PrimeSamplable[N], bits uint, prng io.Reader) (p, q N, err error) {
	if set == nil {
		return *new(N), *new(N), ErrIsNil.WithMessage("nil structure")
	}
	rsaPrivateKey, err := rsa.GenerateKey(prng, int(2*bits))
	if err != nil {
		return *new(N), *new(N), errs.Wrap(err).WithMessage("cannot generate keys pair")
	}

	pBig := rsaPrivateKey.Primes[0]
	qBig := rsaPrivateKey.Primes[1]
	// double check
	if pBig.BitLen() != int(bits) || qBig.BitLen() != int(bits) {
		return *new(N), *new(N), errs.New("p,q have invalid length (%d, %d) - expected %d", pBig.BitLen(), qBig.BitLen(), bits)
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

// generatePrimePair concurrently samples two primes from gen until they are distinct, their product has the required
// keyLen bit length, and every predicate holds for the pair.
func generatePrimePair[N algebra.NatPlusLike[N]](gen *PrimeGenerator[N], keyLen uint, prng io.Reader, predicates ...func(N, N) bool) (p, q N, err error) {
	var nilN N
	if gen == nil || prng == nil {
		return nilN, nilN, ErrIsNil.WithMessage("primeGenerator and prng must not be nil")
	}
	for _, predicate := range predicates {
		if predicate == nil {
			return nilN, nilN, ErrIsNil.WithMessage("predicates must not be nil")
		}
	}
	bits := keyLen / 2

	for {
		var pCandidate, qCandidate N
		g := errgroup.Group{}
		g.Go(func() error {
			var err error
			pCandidate, err = gen.Generate(bits, prng)
			if err != nil {
				return errs.Wrap(err).WithMessage("cannot generate prime")
			}
			return nil
		})
		g.Go(func() error {
			var err error
			qCandidate, err = gen.Generate(bits, prng)
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
		if len(predicates) == 0 || sliceutils.All(predicates, func(predicate func(N, N) bool) bool {
			return predicate(pCandidate, qCandidate)
		}) {

			return pCandidate, qCandidate, nil
		}
	}
}
