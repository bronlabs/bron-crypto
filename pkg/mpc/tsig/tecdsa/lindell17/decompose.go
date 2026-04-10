package lindell17

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

// DecomposeTwoThirds splits a scalar into x', x” with x = 3x' + x” in range [q/3, 2q/3).
func DecomposeTwoThirds[S algebra.PrimeFieldElement[S]](scalar S, prng io.Reader) (xPrime, xDoublePrime S, err error) {
	var nilS S
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](scalar.Structure())
	inRange := func(lowBoundInclusive, highBoundExclusive uint64, x S) (bool, error) {
		ok, err := inEighteenth(lowBoundInclusive, highBoundExclusive, x)
		if err != nil {
			return false, errs.Wrap(err).WithMessage("could not classify scalar interval")
		}
		return ok, nil
	}

	inFirst, err := inRange(0, 3, scalar)
	if err != nil {
		return nilS, nilS, err
	}
	inSecond, err := inRange(3, 6, scalar)
	if err != nil {
		return nilS, nilS, err
	}
	inThird, err := inRange(6, 9, scalar)
	if err != nil {
		return nilS, nilS, err
	}
	inFourth, err := inRange(9, 12, scalar)
	if err != nil {
		return nilS, nilS, err
	}
	inFifth, err := inRange(12, 15, scalar)
	if err != nil {
		return nilS, nilS, err
	}
	inSixth, err := inRange(15, 18, scalar)
	if err != nil {
		return nilS, nilS, err
	}

	switch {
	case inFirst:
		xPrime, err = randomInEighteenth(9, 10, field, prng)
		if err != nil {
			return nilS, nilS, errs.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inSecond:
		xPrime, err = randomInEighteenth(10, 11, field, prng)
		if err != nil {
			return nilS, nilS, errs.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inThird:
		xPrime, err = randomInEighteenth(11, 12, field, prng)
		if err != nil {
			return nilS, nilS, errs.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inFourth:
		xPrime, err = randomInEighteenth(6, 7, field, prng)
		if err != nil {
			return nilS, nilS, errs.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inFifth:
		xPrime, err = randomInEighteenth(7, 8, field, prng)
		if err != nil {
			return nilS, nilS, errs.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inSixth:
		xPrime, err = randomInEighteenth(8, 9, field, prng)
		if err != nil {
			return nilS, nilS, errs.Wrap(err).WithMessage("could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	default:
		return nilS, nilS, ErrFailed.WithMessage("scalar not in expected decomposition range")
	}

	xPrimeInRange, err := inEighteenth(6, 12, xPrime)
	if err != nil {
		return nilS, nilS, errs.Wrap(err).WithMessage("could not validate xPrime range")
	}
	xDoublePrimeInRange, err := inEighteenth(6, 12, xDoublePrime)
	if err != nil {
		return nilS, nilS, errs.Wrap(err).WithMessage("could not validate xDoublePrime range")
	}
	if !xPrimeInRange || !xDoublePrimeInRange {
		return nilS, nilS, ErrFailed.WithMessage("split failed")
	}
	if !xPrime.Add(xPrime).Add(xPrime).Add(xDoublePrime).Equal(scalar) {
		return nilS, nilS, ErrFailed.WithMessage("split failed")
	}
	return xPrime, xDoublePrime, nil
}

func inEighteenth[S algebra.PrimeFieldElement[S]](lowBoundInclusive, highBoundExclusive uint64, x S) (bool, error) {
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](x.Structure())
	orderNat, err := num.N().FromCardinal(field.Order())
	if err != nil {
		return false, errs.Wrap(err).WithMessage("could not convert field order")
	}
	order := orderNat.Lift()

	xNat, err := num.N().FromBytes(x.Bytes())
	if err != nil {
		return false, errs.Wrap(err).WithMessage("could not convert scalar bytes")
	}
	xInt := xNat.Lift()

	x18 := xInt.Mul(num.Z().FromUint64(18))
	low18 := order.Mul(num.Z().FromUint64(lowBoundInclusive))
	high18 := order.Mul(num.Z().FromUint64(highBoundExclusive))
	if low18.IsLessThanOrEqual(x18) && !high18.IsLessThanOrEqual(x18) {
		return true, nil
	}

	return false, nil
}

func randomInEighteenth[S algebra.PrimeFieldElement[S]](lowBoundInclusive, highBoundExclusive uint64, field algebra.PrimeField[S], prng io.Reader) (S, error) {
	var nilS S
	orderNat, err := num.N().FromCardinal(field.Order())
	if err != nil {
		return nilS, errs.Wrap(err).WithMessage("could not convert field order")
	}
	order := orderNat.Lift()

	l18 := order.Mul(num.Z().FromUint64(lowBoundInclusive))
	h18 := order.Mul(num.Z().FromUint64(highBoundExclusive))
	l, _, err := l18.Add(num.Z().FromUint64(17)).EuclideanDivVarTime(num.Z().FromUint64(18))
	if err != nil {
		return nilS, errs.Wrap(err).WithMessage("could not compute lower bound")
	}
	h, _, err := h18.EuclideanDivVarTime(num.Z().FromUint64(18))
	if err != nil {
		return nilS, errs.Wrap(err).WithMessage("could not compute upper bound")
	}
	x, err := num.Z().Random(l, h, prng)
	if err != nil {
		return nilS, errs.Wrap(err).WithMessage("could not generate random rational")
	}
	s, err := field.FromWideBytes(x.Bytes())
	if err != nil {
		return nilS, errs.Wrap(err).WithMessage("could not convert to scalar")
	}
	return s, nil
}
