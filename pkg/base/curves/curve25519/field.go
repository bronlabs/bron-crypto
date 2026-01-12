package curve25519

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
)

const (
	// BaseFieldName is the base field name.
	BaseFieldName = edwards25519.BaseFieldName
)

type (
	BaseField        = edwards25519.BaseField
	BaseFieldElement = edwards25519.BaseFieldElement
)

// NewBaseField returns the base field instance.
func NewBaseField() *BaseField {
	return edwards25519.NewBaseField()
}
