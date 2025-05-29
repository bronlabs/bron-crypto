package trsa

import (
	crand "crypto/rand"
	"crypto/rsa"
	"io"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
)

func ConstructPrivateKey(prng io.Reader, shards ...*Shard) (*rsa.PrivateKey, error) {
	if len(shards) < 2 {
		return nil, errs.NewValidation("expected at least 2 shards")
	}

	n1 := shards[0].N1.Big()
	n2 := shards[0].N2.Big()
	if n1.Cmp(n2) == 0 {
		return nil, errs.NewValidation("shards must have the different N1, N2")
	}

	n := new(big.Int).Mul(n1, n2)
	e := int(shards[0].E)
	for i := 1; i < len(shards); i++ {
		if n1.Cmp(shards[i].N1.Big()) != 0 {
			return nil, errs.NewValidation("shards must have the same N1")
		}
		if n2.Cmp(shards[i].N2.Big()) != 0 {
			return nil, errs.NewValidation("shards must have the same N2")
		}
		if uint64(e) != shards[i].E {
			return nil, errs.NewValidation("shards must have the same E")
		}
	}

	dealer := rep23.NewIntScheme()
	d1Int, err := dealer.Open(sliceutils.Map(shards, func(shard *Shard) *rep23.IntShare { return shard.D1Share })...)
	if err != nil {
		return nil, errs.NewValidation("shards must have consistent D1 share")
	}
	d1 := d1Int.Big()
	if d1.Sign() <= 0 {
		return nil, errs.NewValidation("d1 is not a positive integer")
	}

	d2Int, err := dealer.Open(sliceutils.Map(shards, func(shard *Shard) *rep23.IntShare { return shard.D2Share })...)
	if err != nil {
		return nil, errs.NewValidation("shards must have consistent D1 share")
	}
	d2 := d2Int.Big()
	if d2.Sign() <= 0 {
		return nil, errs.NewValidation("d2 is not a positive integer")
	}

	p1, q1, err := constructPrimes(n1, d1, e, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't construct primes")
	}
	p2, q2, err := constructPrimes(n2, d2, e, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't construct primes")
	}

	one := big.NewInt(1)
	p1MinusOne := new(big.Int).Sub(p1, one)
	q1MinusOne := new(big.Int).Sub(q1, one)
	p2MinusOne := new(big.Int).Sub(p2, one)
	q2MinusOne := new(big.Int).Sub(q2, one)

	totient := new(big.Int).Set(one)
	totient.Mul(totient, p1MinusOne)
	totient.Mul(totient, q1MinusOne)
	totient.Mul(totient, p2MinusOne)
	totient.Mul(totient, q2MinusOne)
	d := new(big.Int).ModInverse(big.NewInt(int64(e)), totient)

	privateKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: e,
		},
		D:      d,
		Primes: []*big.Int{p1, q1, p2, q2},
	}
	privateKey.Precompute()
	return privateKey, nil
}

func constructPrimes(n, d *big.Int, e int, prng io.Reader) (p, q *big.Int, err error) {
	one := big.NewInt(1)
	minusOne := new(big.Int).Sub(n, one)
	f := new(big.Int).Mul(d, big.NewInt(int64(e)))
	f.Sub(f, one)
	s := f.TrailingZeroBits()
	g := new(big.Int).Rsh(f, s)

	for {
		a, err := crand.Int(prng, n)
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "couldn't generate a random sample")
		}
		b := new(big.Int).Exp(a, g, n)
		if b.Cmp(one) == 0 || b.Cmp(minusOne) == 0 {
			continue
		}
		for {
			c := new(big.Int).Mul(b, b)
			c.Mod(c, n)
			if c.Cmp(one) == 0 {
				bMinusOne := new(big.Int).Sub(b, one)
				bPlusOne := new(big.Int).Add(b, one)
				p := new(big.Int).GCD(nil, nil, n, bMinusOne)
				q := new(big.Int).GCD(nil, nil, n, bPlusOne)
				return p, q, nil
			} else if c.Cmp(minusOne) == 0 {
				break
			}

			b.Set(c)
		}
	}
}
