package hash2curve

import (
	"encoding/hex"

	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

type IsogenyParams interface {
	IsogenyMap(xPrime curves.FieldElement) (xNum, xDen, yNum, yDen curves.FieldElement)
}

func NewIsogenyMap(curve curves.Curve) IsogenyParams {
	switch curve.Name() {
	case constants.K256_NAME:
		return NewIsogenyParamsSecp256k1(curve)
	}
	panic("[ISOGENY] curve does not have an implemented isogeny")
}

func ReadConstant(curve curves.Curve, hexString string) curves.FieldElement {
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		panic("[ISOGENY] failed to decode hex string")
	}
	fieldElement, err := curve.FieldElement().SetBytes(bytes)
	if err != nil {
		panic("[ISOGENY] failed to set bytes for field element")
	}
	return fieldElement
}
