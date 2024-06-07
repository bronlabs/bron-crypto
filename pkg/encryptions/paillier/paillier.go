package paillier

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/primes"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

type PlainText = saferith.Nat

type CipherText struct {
	C *saferith.Nat
}

func (c *CipherText) Validate(pk *PublicKey) error {
	if c == nil || c.C == nil || c.C.EqZero() == 1 || c.C.Coprime(pk.N) != 1 {
		return errs.NewValidation("invalid cipher text")
	}

	nnMod, err := pk.GetNNResidueParams()
	if err != nil {
		return errs.WrapValidation(err, "invalid pk")
	}

	if !saferithUtils.NatIsLess(c.C, nnMod.GetModulus().Nat()) {
		return errs.NewValidation("invalid cipher text")
	}

	return nil
}

func KeyGenWithPrimeGenerator(bits int, prng io.Reader, primeGen func(bits int, prng io.Reader) (p, q *saferith.Nat, err error)) (*PublicKey, *SecretKey, error) {
	p, q, err := primeGen(bits, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "keygen failed")
	}

	sk, err := NewSecretKey(p, q)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "keygen failed")
	}

	return &sk.PublicKey, sk, nil
}

func KeyGen(bits int, prng io.Reader) (*PublicKey, *SecretKey, error) {
	return KeyGenWithPrimeGenerator(bits, prng, primes.GeneratePrimePair)
}
