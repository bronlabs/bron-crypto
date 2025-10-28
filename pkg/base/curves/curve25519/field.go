package curve25519

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
)

const (
	BaseFieldName = edwards25519.BaseFieldName
)

type (
	BaseField        = edwards25519.BaseField
	BaseFieldElement = edwards25519.BaseFieldElement
)

func NewBaseField() *BaseField {
	return edwards25519.NewBaseField()
}
