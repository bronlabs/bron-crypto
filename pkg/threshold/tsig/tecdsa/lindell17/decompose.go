package lindell17

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

var (
	three       = num.Z().FromUint64(3)
	four        = num.Z().FromUint64(4)
	nine        = num.Z().FromUint64(9)
	ten         = num.Z().FromUint64(10)
	eighteen, _ = num.NPlus().FromUint64(18)
)

// DecomposeTwoThirds decomposes x into x1 and x2 such that x = 3*x1 + x2 mod q and q/3 <= x1,x2 < 2q/3 where q is the order of the prime subgroup.
func DecomposeTwoThirds[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve ecdsa.Curve[P, B, S], x S, prng io.Reader) (x1, x2 S, err error) {
	if curve == nil {
		return x1, x2, errs.NewIsNil("curve must not be nil")
	}
	xInt, err := num.Z().FromBytes(x.Bytes())
	if err != nil {
		return x1, x2, errs.WrapFailed(err, "could not convert x to Int")
	}
	order := curve.Order()
	q, err := num.Z().FromCardinal(order)
	if err != nil {
		return x1, x2, errs.WrapFailed(err, "could not convert order to Int")
	}
	var x1Nat *num.Nat
	for k := range uint(3) {
		if inEighteenth(k, q, xInt) {
			x1Nat, err = sampleCase1(k, q, prng)
			if err != nil {
				return x1, x2, errs.WrapFailed(err, "could not convert x to Nat")
			}
			break
		}
	}
	for k := uint(3); k < 6; k++ {
		if inEighteenth(k, q, xInt) {
			x1Nat, err = sampleCase2(k, q, prng)
			if err != nil {
				return x1, x2, errs.WrapFailed(err, "could not convert x to Nat")
			}
			break
		}
	}
	if x1Nat == nil {
		return x1, x2, errs.NewFailed("x does not fall into any eighteenth interval")
	}
	x1, err = curve.ScalarField().FromNat(x1Nat.Value())
	if err != nil {
		return x1, x2, errs.WrapFailed(err, "could not convert x1 to field element")
	}
	x2 = x.Sub(x1.Double().Add(x1))
	return x1, x2, nil
}

// x \in [\frac{3k}{18} q, \frac{3(k+1)}{18} q)]
func inEighteenth(k uint, q, x *num.Int) bool {
	kInt := num.Z().FromUint64(uint64(k))
	l, err := num.Q().New(three.Mul(kInt).Mul(q), eighteen)
	if err != nil {
		panic(err)
	}
	h, err := num.Q().New(three.Mul(kInt.Increment()).Mul(q), eighteen)
	if err != nil {
		panic(err)
	}
	return l.IsLessThanOrEqual(x.Rat()) && x.Rat().IsLessThanOrEqual(h) && !x.Rat().Equal(h)
}

// Case1: [\frac{9+k}{18} q, \frac{9+(k+1)}{18} q)]
func sampleCase1(k uint, q *num.Int, prng io.Reader) (*num.Nat, error) {
	kInt := num.Z().FromUint64(uint64(k))
	l, err := num.Q().New((nine.Add(kInt)).Mul(q), eighteen)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct lower bound")
	}
	h, err := num.Q().New((ten.Add(kInt)).Mul(q), eighteen)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct upper bound")
	}

	x, err := num.Q().RandomInt(l.Canonical(), h.Canonical(), prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random rational")
	}
	xNat, err := num.N().FromInt(x)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert to Nat")
	}
	return xNat, nil
}

// Case2: [\frac{3+k}{18} q, \frac{3+(k+1)}{18} q)]
func sampleCase2(k uint, q *num.Int, prng io.Reader) (*num.Nat, error) {
	kInt := num.Z().FromUint64(uint64(k))
	l, err := num.Q().New((three.Add(kInt)).Mul(q), eighteen)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct lower bound")
	}
	h, err := num.Q().New((four.Add(kInt)).Mul(q), eighteen)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct upper bound")
	}

	x, err := num.Q().RandomInt(l.Canonical(), h.Canonical(), prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random rational")
	}
	xNat, err := num.N().FromInt(x)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert to Nat")
	}
	return xNat, nil
}
