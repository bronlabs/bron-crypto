package primes

import (
	crand "crypto/rand"
	"crypto/rsa"
	"io"
	"math"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// GenerateSafePrime creates a prime number `p`
// where (`p`-1)/2 is also prime with at least `bits`.
func GenerateSafePrime(bits uint) (*saferith.Nat, error) {
	if bits < 3 {
		return nil, errs.NewFailed("safe prime size must be at least 3-bits")
	}

	var p *big.Int
	var err error
	checks := int(math.Max(float64(bits)/16, 8))
	for {
		// rand.Prime throws an error if bits < 2
		// -1 so the Sophie-Germain prime is 1023 bits
		// and the Safe prime is 1024
		p, err = crand.Prime(crand.Reader, int(bits)-1)
		if err != nil {
			return nil, errs.WrapFailed(err, "reading from crand")
		}
		p.Add(p.Lsh(p, 1), big.NewInt(1))

		if p.ProbablyPrime(checks) {
			break
		}
	}

	return new(saferith.Nat).SetBig(p, int(bits)), nil
}

func GenerateSafePrimePair(bits uint) (p, q *saferith.Nat, err error) {
	values := make(chan *saferith.Nat, 2)
	errors := make(chan error, 2)

	p = nil
	q = nil
	for p == q || p.Eq(q) != 0 {
		for range []int{1, 2} {
			go func() {
				value, err := GenerateSafePrime(bits)
				values <- value
				errors <- err
			}()
		}

		for _, err := range []error{<-errors, <-errors} {
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot generate same primes")
			}
		}

		p, q = <-values, <-values
	}

	return p, q, nil
}

func GeneratePrimePair(bits int, prng io.Reader) (p, q *saferith.Nat, err error) {
	if bits < 3 {
		return nil, nil, errs.NewFailed("bits < 3")
	}
	rsaPrivateKey, err := rsa.GenerateKey(prng, 2*bits)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot generate keys pair")
	}

	pBig := rsaPrivateKey.Primes[0]
	qBig := rsaPrivateKey.Primes[1]
	// double check
	if pBig.BitLen() < bits || qBig.BitLen() < bits {
		return nil, nil, errs.WrapFailed(err, "p,q have invalid length")
	}

	p = new(saferith.Nat).SetBig(pBig, bits)
	q = new(saferith.Nat).SetBig(qBig, bits)
	return p, q, nil
}
