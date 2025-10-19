package nt

import (
	crand "crypto/rand"
	"crypto/rsa"
	"io"
	"math"
	"math/big"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
)

type LiftableToZ[I algebra.IntLike[I]] = internal.LiftableToZ[I]

type PrimeSamplable[E algebra.UniqueFactorizationMonoidElement[E]] interface {
	algebra.UniqueFactorizationMonoid[E]
	FromBig(*big.Int) (E, error)
}

func GenerateSafePrime[N algebra.UniqueFactorizationMonoidElement[N]](set PrimeSamplable[N], bits uint) (N, error) {
	if bits < 3 {
		return *new(N), errs.NewFailed("safe prime size must be at least 3-bits")
	}
	if set == nil {
		return *new(N), errs.NewFailed("nil structure")
	}
	var p *big.Int
	var err error
	checks := int(math.Max(float64(bits)/16, 8))
	for {
		// TODO: generate the number of checks via sage.

		// rand.Prime throws an error if bits < 2
		// -1 so the Sophie-Germain prime is 1023 bits
		// and the Safe prime is 1024
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

func GenerateSafePrimePair[N algebra.UniqueFactorizationMonoidElement[N]](set PrimeSamplable[N], bits uint) (p, q N, err error) {
	g := errgroup.Group{}
	for p.Equal(q) {
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
	}
	return p, q, nil
}

func GeneratePrimePair[N algebra.UniqueFactorizationMonoidElement[N]](set PrimeSamplable[N], bits uint, prng io.Reader) (p, q N, err error) {
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
