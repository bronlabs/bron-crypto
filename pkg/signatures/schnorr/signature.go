package schnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type Signature[F any, M any, P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] struct {
	Variant Variant[F, M, P, B, S]

	E S
	R P
	S S

	_ ds.Incomparable
}

func NewSignature[F Variant[F, M, P, B, S], M any, P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]](variant Variant[F, M, P, B, S], e S, r P, s S) *Signature[F, M, P, B, S] {
	return &Signature[F, M, P, B, S]{
		Variant: variant,
		E:       e,
		R:       r,
		S:       s,
	}
}

func (s *Signature[F, M, P, B, S]) MarshalBinary() (data []byte, err error) {
	return s.Variant.SerializeSignature(s), nil
}
