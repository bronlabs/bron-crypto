package curve25519

import "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"

const (
	// ScalarFieldName is the scalar field name.
	ScalarFieldName = edwards25519.ScalarFieldName
)

type (
	ScalarField = edwards25519.ScalarField
	Scalar      = edwards25519.Scalar
)

// NewScalarField returns the scalar field instance.
func NewScalarField() *ScalarField {
	return edwards25519.NewScalarField()
}

// NewScalar returns a new scalar.
func NewScalar(v uint64) *Scalar {
	return edwards25519.NewScalar(v)
}
