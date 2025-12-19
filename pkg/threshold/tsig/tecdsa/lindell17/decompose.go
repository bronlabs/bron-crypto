package lindell17

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

// DecomposeTwoThirds splits a scalar into x' and x” in [q/6, 2q/3) such that x + x' + x' + x' + x” = x.
func DecomposeTwoThirds[S algebra.PrimeFieldElement[S]](scalar S, prng io.Reader) (xPrime, xDoublePrime S, err error) {
	var nilS S
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](scalar.Structure())

	switch {
	case inEighteenth(0, 3, scalar):
		xPrime, err = randomInEighteenth(9, 10, field, prng)
		if err != nil {
			return nilS, nilS, errs2.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(3, 6, scalar):
		xPrime, err = randomInEighteenth(10, 11, field, prng)
		if err != nil {
			return nilS, nilS, errs2.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(6, 9, scalar):
		xPrime, err = randomInEighteenth(11, 12, field, prng)
		if err != nil {
			return nilS, nilS, errs2.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(9, 12, scalar):
		xPrime, err = randomInEighteenth(6, 7, field, prng)
		if err != nil {
			return nilS, nilS, errs2.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(12, 15, scalar):
		xPrime, err = randomInEighteenth(7, 8, field, prng)
		if err != nil {
			return nilS, nilS, errs2.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(15, 18, scalar):
		xPrime, err = randomInEighteenth(8, 9, field, prng)
		if err != nil {
			return nilS, nilS, errs2.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	default:
		panic("this should never happen")
	}

	// double check
	if !inEighteenth(6, 12, xPrime) || !inEighteenth(6, 12, xDoublePrime) {
		return nilS, nilS, ErrFailed.WithMessage("split failed")
	}
	if !xPrime.Add(xPrime).Add(xPrime).Add(xDoublePrime).Equal(scalar) {
		return nilS, nilS, ErrFailed.WithMessage("split failed")
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
	l, _, err := l18.Add(num.Z().FromUint64(17)).EuclideanDivVarTime(num.Z().FromUint64(18))
	if err != nil {
		return nilS, errs2.Wrap(err).WithMessage("could not compute lower bound")
	}
	h, _, err := h18.EuclideanDivVarTime(num.Z().FromUint64(18))
	if err != nil {
		return nilS, errs2.Wrap(err).WithMessage("could not compute upper bound")
	}
	x, err := num.Z().Random(l, h, prng)
	if err != nil {
		return nilS, errs2.Wrap(err).WithMessage("could not generate random rational")
	}
	s, err := field.FromWideBytes(x.Bytes())
	if err != nil {
		return nilS, errs2.Wrap(err).WithMessage("could not convert to scalar")
	}
	return s, nil
}
