package fields

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"golang.org/x/exp/constraints"
)

func IsNegative[FP impl.PrimeFieldElementPtr[FP, F], F any](v *F) (neg ct.Bool) {
	var vNeg F
	FP(&vNeg).Neg(v)
	gt, _ := SliceCmpLE(FP(v).Limbs(), FP(&vNeg).Limbs())
	return gt
}

func IsOdd[FP impl.PrimeFieldElementPtr[FP, F], F any](v *F) (odd ct.Bool) {
	return ct.Bool(FP(v).Bytes()[0] & 0b1)
}

func Degree[FP impl.FiniteFieldElementPtr[FP, F], F any]() uint64 {
	return FP(nil).Degree()
}

// SliceCmpLE returns 1 if x > y, 0 if x == y, -1 if x < y,
// where the slice is little-endian limb-like representation.
func SliceCmpLE[S ~[]E, E constraints.Unsigned](x, y S) (gt, lt ct.Bool) {
	if len(x) != len(y) {
		panic("ct: slices have different lengths")
	}

	gt = ct.Bool(0)
	lt = ct.Bool(0)
	for i := len(x) - 1; i >= 0; i-- {
		gt |= ct.Greater(x[i], y[i]) & ^lt
		lt |= ct.Less(x[i], y[i]) & ^gt
	}
	return gt, lt
}
