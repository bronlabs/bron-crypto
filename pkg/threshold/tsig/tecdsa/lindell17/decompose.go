package lindell17

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

func DecomposeTwoThirds[S algebra.PrimeFieldElement[S]](scalar S, prng io.Reader) (xPrime, xDoublePrime S, err error) {
	var nilS S
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](scalar.Structure())

	switch {
	case inEighteenth(0, 3, scalar):
		xPrime, err = randomInEighteenth(9, 10, field, prng)
		if err != nil {
			return nilS, nilS, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(3, 6, scalar):
		xPrime, err = randomInEighteenth(10, 11, field, prng)
		if err != nil {
			return nilS, nilS, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(6, 9, scalar):
		xPrime, err = randomInEighteenth(11, 12, field, prng)
		if err != nil {
			return nilS, nilS, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(9, 12, scalar):
		xPrime, err = randomInEighteenth(6, 7, field, prng)
		if err != nil {
			return nilS, nilS, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(12, 15, scalar):
		xPrime, err = randomInEighteenth(7, 8, field, prng)
		if err != nil {
			return nilS, nilS, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(15, 18, scalar):
		xPrime, err = randomInEighteenth(8, 9, field, prng)
		if err != nil {
			return nilS, nilS, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	default:
		panic("this should never happen")
	}

	// double check
	if !inEighteenth(6, 12, xPrime) || !inEighteenth(6, 12, xDoublePrime) {
		return nilS, nilS, errs.NewFailed("split failed")
	}
	if !xPrime.Add(xPrime).Add(xPrime).Add(xDoublePrime).Equal(scalar) {
		return nilS, nilS, errs.NewFailed("split failed")
	}
	return xPrime, xDoublePrime, nil
}

func inEighteenth[S algebra.PrimeFieldElement[S]](lowBoundInclusive, highBoundExclusive uint64, x S) bool {
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](x.Structure())
	orderNat, err := num.N().FromCardinal(field.Order())
	if err != nil {
		// this should never happen
		panic(err)
	}
	order := orderNat.Lift()

	// TODO: would be nice to have PrimeFieldElement.ToInt() or something
	xNat, err := num.N().FromBytes(x.Bytes())
	if err != nil {
		// this should never happen
		panic(err)
	}
	xInt := xNat.Lift()

	x18 := xInt.Mul(num.Z().FromUint64(18))
	low18 := order.Mul(num.Z().FromUint64(lowBoundInclusive))
	high18 := order.Mul(num.Z().FromUint64(highBoundExclusive))
	if low18.IsLessThanOrEqual(x18) && !high18.IsLessThanOrEqual(x18) {
		return true
	}

	return false
}

func randomInEighteenth[S algebra.PrimeFieldElement[S]](lowBoundInclusive, highBoundExclusive uint64, field algebra.PrimeField[S], prng io.Reader) (S, error) {
	var nilS S
	orderNat, err := num.N().FromCardinal(field.Order())
	if err != nil {
		// this should never happen
		panic(err)
	}
	order := orderNat.Lift()

	l18 := order.Mul(num.Z().FromUint64(lowBoundInclusive))
	h18 := order.Mul(num.Z().FromUint64(highBoundExclusive))
	l, _, err := l18.Add(num.Z().FromUint64(17)).EuclideanDiv(num.Z().FromUint64(18))
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not compute lower bound")
	}
	h, _, err := h18.EuclideanDiv(num.Z().FromUint64(18))
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not compute upper bound")
	}
	x, err := num.Z().Random(l, h, prng)
	if err != nil {
		return nilS, errs.WrapRandomSample(err, "could not generate random rational")
	}
	s, err := field.FromWideBytes(x.Bytes())
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not convert to scalar")
	}
	return s, nil
}

// import (
// 	"io"

// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
// 	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
// )

// var (
// 	three       = num.Z().FromUint64(3)
// 	four        = num.Z().FromUint64(4)
// 	nine        = num.Z().FromUint64(9)
// 	ten         = num.Z().FromUint64(10)
// 	eighteen, _ = num.NPlus().FromUint64(18)
// )

// // DecomposeTwoThirds decomposes x into x1 and x2 such that x = 3*x1 + x2 mod q and q/3 <= x1,x2 < 2q/3 where q is the order of the prime subgroup.
// func DecomposeTwoThirds[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve ecdsa.Curve[P, B, S], x S, prng io.Reader) (x1, x2 S, err error) {
// 	if curve == nil {
// 		return x1, x2, errs.NewIsNil("curve must not be nil")
// 	}
// 	xInt, err := num.Z().FromBytes(x.Bytes())
// 	if err != nil {
// 		return x1, x2, errs.WrapFailed(err, "could not convert x to Int")
// 	}
// 	order := curve.Order()
// 	q, err := num.Z().FromCardinal(order)
// 	if err != nil {
// 		return x1, x2, errs.WrapFailed(err, "could not convert order to Int")
// 	}
// 	var x1Nat *num.Nat
// 	for k := range uint(3) {
// 		if inEighteenth(k, q, xInt) {
// 			x1Nat, err = sampleCase1(k, q, prng)
// 			if err != nil {
// 				return x1, x2, errs.WrapFailed(err, "could not convert x to Nat")
// 			}
// 			break
// 		}
// 	}
// 	for k := uint(3); k < 6; k++ {
// 		if inEighteenth(k, q, xInt) {
// 			x1Nat, err = sampleCase2(k, q, prng)
// 			if err != nil {
// 				return x1, x2, errs.WrapFailed(err, "could not convert x to Nat")
// 			}
// 			break
// 		}
// 	}
// 	if x1Nat == nil {
// 		return x1, x2, errs.NewFailed("x does not fall into any eighteenth interval")
// 	}
// 	x1, err = curve.ScalarField().FromNat(x1Nat.Value())
// 	if err != nil {
// 		return x1, x2, errs.WrapFailed(err, "could not convert x1 to field element")
// 	}
// 	x2 = x.Sub(x1.Double().Add(x1))
// 	return x1, x2, nil
// }

// // x \in [\frac{3k}{18} q, \frac{3(k+1)}{18} q)]
// func inEighteenth(k uint, q, x *num.Int) bool {
// 	kInt := num.Z().FromUint64(uint64(k))
// 	l, err := num.Q().New(three.Mul(kInt).Mul(q), eighteen)
// 	if err != nil {
// 		panic(err)
// 	}
// 	h, err := num.Q().New(three.Mul(kInt.Increment()).Mul(q), eighteen)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return l.IsLessThanOrEqual(x.Rat()) && x.Rat().IsLessThanOrEqual(h) && !x.Rat().Equal(h)
// }

// // Case1: [\frac{9+k}{18} q, \frac{9+(k+1)}{18} q)]
// func sampleCase1(k uint, q *num.Int, prng io.Reader) (*num.Nat, error) {
// 	kInt := num.Z().FromUint64(uint64(k))
// 	l, err := num.Q().New((nine.Add(kInt)).Mul(q), eighteen)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not construct lower bound")
// 	}
// 	h, err := num.Q().New((ten.Add(kInt)).Mul(q), eighteen)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not construct upper bound")
// 	}

// 	x, err := num.Q().RandomInt(l.Canonical(), h.Canonical(), prng)
// 	if err != nil {
// 		return nil, errs.WrapRandomSample(err, "could not generate random rational")
// 	}
// 	xNat, err := num.N().FromInt(x)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not convert to Nat")
// 	}
// 	return xNat, nil
// }

// // Case2: [\frac{3+k}{18} q, \frac{3+(k+1)}{18} q)]
// func sampleCase2(k uint, q *num.Int, prng io.Reader) (*num.Nat, error) {
// 	kInt := num.Z().FromUint64(uint64(k))
// 	l, err := num.Q().New((three.Add(kInt)).Mul(q), eighteen)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not construct lower bound")
// 	}
// 	h, err := num.Q().New((four.Add(kInt)).Mul(q), eighteen)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not construct upper bound")
// 	}

// 	x, err := num.Q().RandomInt(l.Canonical(), h.Canonical(), prng)
// 	if err != nil {
// 		return nil, errs.WrapRandomSample(err, "could not generate random rational")
// 	}
// 	xNat, err := num.N().FromInt(x)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not convert to Nat")
// 	}
// 	return xNat, nil
// }
