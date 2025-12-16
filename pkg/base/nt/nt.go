package nt

import (
	crand "crypto/rand"
	"crypto/rsa"
	"io"
	"maps"
	"math/big"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type PrimeSamplable[E algebra.NatPlusLike[E]] interface {
	FromBig(*big.Int) (E, error)
}

func MillerRabinChecks(bits uint) int {
	if len(millerRabinIterations) == 0 {
		panic("millerRabinIterations is not initialized")
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
	panic("millerRabinIterations is not properly initialized")
}

func GenerateSafePrime[N algebra.NatPlusLike[N]](set PrimeSamplable[N], bits uint) (N, error) {
	if bits < 3 {
		return *new(N), errs.NewFailed("safe prime size must be at least 3-bits")
	}
	if set == nil {
		return *new(N), errs.NewFailed("nil structure")
	}
	var p *big.Int
	var err error
	checks := MillerRabinChecks(bits)
	for {
		p, err = crand.Prime(crand.Reader, int(bits)-1)
		if err != nil {
			return *new(N), errs.WrapFailed(err, "reading from crand")
		}
		p.Add(p.Lsh(p, 1), big.NewInt(1))

		if p.ProbablyPrime(checks) {
			break
		}
	}
	n, err := set.FromBig(p)
	if err != nil {
		return *new(N), errs.WrapFailed(err, "cannot convert prime to structure")
	}
	return n, nil
}

func GenerateSafePrimePair[N algebra.NatPlusLike[N]](set PrimeSamplable[N], bits uint) (p, q N, err error) {
	g := errgroup.Group{}
	for {
		g.Go(func() error {
			p, err = GenerateSafePrime(set, bits)
			if err != nil {
				return err
			}
			return nil
		})
		g.Go(func() error {
			q, err = GenerateSafePrime(set, bits)
			if err != nil {
				return err
			}
			return nil
		})
		if err := g.Wait(); err != nil {
			return *new(N), *new(N), errs.WrapFailed(err, "cannot generate same primes")
		}
		if !p.Equal(q) {
			return p, q, nil
		}
	}
}

func GeneratePrimePair[N algebra.NatPlusLike[N]](set PrimeSamplable[N], bits uint, prng io.Reader) (p, q N, err error) {
	if set == nil {
		return *new(N), *new(N), errs.NewFailed("nil structure")
	}
	rsaPrivateKey, err := rsa.GenerateKey(prng, int(2*bits))
	if err != nil {
		return *new(N), *new(N), errs.WrapFailed(err, "cannot generate keys pair")
	}

	pBig := rsaPrivateKey.Primes[0]
	qBig := rsaPrivateKey.Primes[1]
	// double check
	if pBig.BitLen() != int(bits) || qBig.BitLen() != int(bits) {
		return *new(N), *new(N), errs.WrapFailed(err, "p,q have invalid length (%d, %d) - expected %d", pBig.BitLen(), qBig.BitLen(), bits)
	}
	p, err = set.FromBig(pBig)
	if err != nil {
		return *new(N), *new(N), errs.WrapFailed(err, "cannot convert p to structure")
	}
	q, err = set.FromBig(qBig)
	if err != nil {
		return *new(N), *new(N), errs.WrapFailed(err, "cannot convert q to structure")
	}
	return p, q, nil
}
