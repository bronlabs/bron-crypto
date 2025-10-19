package fields

import (
	"golang.org/x/exp/constraints"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func IsNegative[FP impl.PrimeFieldElementPtr[FP, F], F any](v *F) (neg ct.Bool) {
	var vNeg F
	FP(&vNeg).Neg(v)
	_, _, gt := SliceCmpLE(FP(v).Limbs(), FP(&vNeg).Limbs())
	return gt
}

func IsOdd[FP impl.PrimeFieldElementPtr[FP, F], F any](v *F) (odd ct.Bool) {
	return ct.Bool(FP(v).Bytes()[0] & 0b1)
}

func Degree[FP impl.FiniteFieldElementPtr[FP, F], F any]() uint64 {
	return FP(nil).Degree()
}

// the slice is little-endian limb-like representation.
func SliceCmpLE[S ~[]E, E constraints.Unsigned](x, y S) (lt, eq, gt ct.Bool) {
	if len(x) != len(y) {
		panic("ct: slices have different lengths")
	}

	gt = 0
	lt = 0
	eq = 1

	for i := len(x) - 1; i >= 0; i-- {
		isGt := ct.Greater(x[i], y[i])
		isLt := ct.Less(x[i], y[i])
		isEq := ct.Equal(x[i], y[i])

		// mask propagation to preserve first significant comparison
		gt |= isGt & ^lt
		lt |= isLt & ^gt
		eq &= isEq
	}
	return lt, eq, gt
}
