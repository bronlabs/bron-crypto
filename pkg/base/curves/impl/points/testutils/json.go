package testutils

import (
	"encoding/json"
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	fieldsTu "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields/testutils"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

type PointJson[FP fields.FiniteFieldElementPtrConstraint[FP, F], PP pointsImpl.PointPtrConstraint[FP, PP, P], F, P any] struct {
	V P
}

func (p *PointJson[FP, PP, F, P]) UnmarshalJSON(data []byte) error {
	type innerType struct {
		X fieldsTu.FiniteFieldElementJson[FP, F] `json:"x"`
		Y fieldsTu.FiniteFieldElementJson[FP, F] `json:"y"`
	}
	var innerData innerType
	err := json.Unmarshal(data, &innerData)
	if err != nil {
		return err
	}

	ok := PP(&p.V).SetAffine(FP(&innerData.X.V), FP(&innerData.Y.V))
	if ok != 1 {
		return fmt.Errorf("invalid point")
	}

	return nil
}
