package testutils

import (
	"encoding/json"
	"fmt"
	"math/big"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
)

type FiniteFieldElementJson[FP impl.FiniteFieldElementPtr[FP, F], F any] struct {
	V F
}

func (f *FiniteFieldElementJson[FP, F]) UnmarshalJSON(data []byte) error {
	type innerType []string
	var innerData innerType
	err := json.Unmarshal(data, &innerData)
	if err != nil {
		return err
	}

	uniformBytes := make([][]byte, len(innerData))
	for i, s := range innerData {
		bi, ok := new(big.Int).SetString(s, 0)
		if !ok {
			return fmt.Errorf("invalid number string: %s", s)
		}
		biBytes := bi.Bytes()
		slices.Reverse(biBytes)
		uniformBytes[i] = biBytes
	}

	ok := FP(&f.V).SetUniformBytes(uniformBytes...)
	if ok != 1 {
		return fmt.Errorf("invalid uniform bytes")
	}

	return nil
}
