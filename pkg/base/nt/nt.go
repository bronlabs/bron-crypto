package nt

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type LiftableToZ[I algebra.IntLike[I]] internal.LiftableToZ[I]

type Ascending[E LiftableToZ[I], I algebra.IntLike[I]] []E

func (a Ascending[E, I]) Len() int {
	return len(a)
}

func (a Ascending[E, I]) Less(i, j int) bool {
	return a[i].Lift().IsLessThanOrEqual(a[j].Lift()) && !a[j].Lift().IsLessThanOrEqual(a[i].Lift())
}

func (a Ascending[E, I]) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func Max[E LiftableToZ[I], I algebra.IntLike[I]](first E, rest ...E) E {
	return sliceutils.Reduce(rest, first, func(a, b E) E {
		if a.Lift().IsLessThanOrEqual(b.Lift()) {
			return b
		}
		return a
	})
}

func Min[E LiftableToZ[I], I algebra.IntLike[I]](first E, rest ...E) E {
	return sliceutils.Reduce(rest, first, func(a, b E) E {
		if a.Lift().IsLessThanOrEqual(b.Lift()) {
			return a
		}
		return b
	})
}
