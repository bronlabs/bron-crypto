package bf128_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"

	_ "embed"
)

type jsonBF128Element bf128.FieldElement

func (e *jsonBF128Element) UnmarshalJSON(bytes []byte) error {
	var repr string
	err := json.Unmarshal(bytes, &repr)
	if err != nil {
		return err
	}
	beBytes, err := hex.DecodeString(repr)
	if err != nil {
		return err
	}
	if len(beBytes) != 16 {
		return errs.NewFailed("invalid")
	}
	el, err := bf128.NewField().FromBytes(beBytes)
	if err != nil {
		return err
	}
	*e = jsonBF128Element(*el)
	return nil
}

type testVectors struct {
	Mul []struct {
		X jsonBF128Element `json:"x"`
		Y jsonBF128Element `json:"y"`
		Z jsonBF128Element `json:"z"`
	} `json:"mul"`
	Add []struct {
		X jsonBF128Element `json:"x"`
		Y jsonBF128Element `json:"y"`
		Z jsonBF128Element `json:"z"`
	} `json:"add"`
	Sub []struct {
		X jsonBF128Element `json:"x"`
		Y jsonBF128Element `json:"y"`
		Z jsonBF128Element `json:"z"`
	} `json:"sub"`
	Neg []struct {
		X jsonBF128Element `json:"x"`
		Z jsonBF128Element `json:"z"`
	} `json:"neg"`
}

//go:embed testvectors/vectors.json
var testVectorsData string

func TestVectors(t *testing.T) {
	var vectors testVectors
	err := json.Unmarshal([]byte(testVectorsData), &vectors)
	require.NoError(t, err)

	t.Run("mul", func(t *testing.T) {
		t.Parallel()
		for _, mulVector := range vectors.Mul {
			x := (*bf128.FieldElement)(&mulVector.X)
			y := (*bf128.FieldElement)(&mulVector.Y)
			expectedZ := (*bf128.FieldElement)(&mulVector.Z)
			actualZ := x.Mul(y)
			require.True(t, expectedZ.Equal(actualZ))
		}
	})

	t.Run("add", func(t *testing.T) {
		t.Parallel()
		for _, addVector := range vectors.Add {
			x := (*bf128.FieldElement)(&addVector.X)
			y := (*bf128.FieldElement)(&addVector.Y)
			expectedZ := (*bf128.FieldElement)(&addVector.Z)
			actualZ := x.Sub(y)
			require.True(t, expectedZ.Equal(actualZ))
		}
	})

	t.Run("sub", func(t *testing.T) {
		t.Parallel()
		for _, subVector := range vectors.Sub {
			x := (*bf128.FieldElement)(&subVector.X)
			y := (*bf128.FieldElement)(&subVector.Y)
			expectedZ := (*bf128.FieldElement)(&subVector.Z)
			actualZ := x.Sub(y)
			require.True(t, expectedZ.Equal(actualZ))
		}
	})

	t.Run("neg", func(t *testing.T) {
		t.Parallel()
		for _, negVector := range vectors.Neg {
			x := (*bf128.FieldElement)(&negVector.X)
			expectedZ := (*bf128.FieldElement)(&negVector.Z)
			actualZ := x.Neg()
			require.True(t, expectedZ.Equal(actualZ))
		}
	})
}
