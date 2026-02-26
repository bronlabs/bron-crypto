package constructions_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
)

func _[R algebra.Ring[E], E algebra.RingElement[E]]() {
	var (
		_ algebra.Algebra[*constructions.RegularAlgebraElement[E], E]        = (*constructions.RegularAlgebra[R, E])(nil)
		_ algebra.AlgebraElement[*constructions.RegularAlgebraElement[E], E] = (*constructions.RegularAlgebraElement[E])(nil)
	)
}
