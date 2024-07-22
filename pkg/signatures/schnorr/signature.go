package schnorr

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

type Signature[F any, M any] struct {
	Variant Variant[F, M]

	E curves.Scalar
	R curves.Point
	S curves.Scalar

	_ ds.Incomparable
}

func NewSignature[F Variant[F, M], M any](variant Variant[F, M], e curves.Scalar, r curves.Point, s curves.Scalar) *Signature[F, M] {
	return &Signature[F, M]{
		Variant: variant,
		E:       e,
		R:       r,
		S:       s,
	}
}

func (s *Signature[F, M]) MarshalBinary() (data []byte, err error) {
	return s.Variant.SerializeSignature(s), nil
}
