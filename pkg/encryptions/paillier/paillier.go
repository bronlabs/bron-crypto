package paillier

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/primes"
)

type CipherText struct {
	C *saferith.Nat
}

func (c *CipherText) Validate(pk *PublicKey) error {
	n2 := pk.GetPrecomputed().N2Modulus
	if c == nil || c.C == nil || c.C.EqZero() == 1 || c.C.IsUnit(n2) != 1 {
		return errs.NewValidation("invalid cipher text")
	}

	_, _, less := c.C.Cmp(n2.Nat())
	if less != 1 {
		return errs.NewValidation("invalid cipher text")
	}

	return nil
}

func KeyGenWithPrimeGenerator(bits int, prng io.Reader, primeGen func(bits int, prng io.Reader) (p, q *saferith.Nat, err error)) (*PublicKey, *SecretKey, error) {
	p, q, err := primeGen(bits, prng)
	if err != nil {
		return nil, nil, err
	}

	sk, err := NewSecretKey(p, q)
	if err != nil {
		return nil, nil, err
	}

	return &sk.PublicKey, sk, nil
}

func KeyGen(bits int, prng io.Reader) (*PublicKey, *SecretKey, error) {
	return KeyGenWithPrimeGenerator(bits, prng, primes.GeneratePrimePair2)
}
