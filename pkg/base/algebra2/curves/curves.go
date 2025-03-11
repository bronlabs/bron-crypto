package curves

import (
	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
)

type (
	Curve[P algebra.Point[P, F, S], F algebra.RingElement[F], S algebra.RingElement[S]] algebra.Curve[P, F, S]
	Point[P algebra.Point[P, F, S], F algebra.RingElement[F], S algebra.RingElement[S]] algebra.Point[P, F, S]
)
