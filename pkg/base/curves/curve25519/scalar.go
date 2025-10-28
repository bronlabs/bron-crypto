package curve25519

import "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"

const (
	ScalarFieldName = edwards25519.ScalarFieldName
)

type (
	ScalarField = edwards25519.ScalarField
	Scalar      = edwards25519.Scalar
)

func NewScalarField() *ScalarField {
	return edwards25519.NewScalarField()
}

func NewScalar(v uint64) *Scalar {
	return edwards25519.NewScalar(v)
}
