package bf128_test

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"

	_ "embed"
)

//go:embed testvectors/vectors.json
var testVectorsData string

func TestVectors(t *testing.T) {
	t.Parallel()
	var vectors testVectors
	err := json.Unmarshal([]byte(testVectorsData), &vectors)
	require.NoError(t, err)

	testBinaryOp(t, vectors.Mul, (*bf128.FieldElement).Mul)
	testBinaryOp(t, vectors.Add, (*bf128.FieldElement).Add)
	testBinaryOp(t, vectors.Sub, (*bf128.FieldElement).Sub)
	testUnaryOp(t, vectors.Neg, (*bf128.FieldElement).Neg)
	testBinaryTryOp(t, vectors.Div, (*bf128.FieldElement).TryDiv)
	testUnaryTryOp(t, vectors.Inv, (*bf128.FieldElement).TryInv)
}

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

type binaryOpVector struct {
	X jsonBF128Element `json:"x"`
	Y jsonBF128Element `json:"y"`
	Z jsonBF128Element `json:"z"`
}

func (v *binaryOpVector) getX() *bf128.FieldElement {
	return (*bf128.FieldElement)(&v.X)
}

func (v *binaryOpVector) getY() *bf128.FieldElement {
	return (*bf128.FieldElement)(&v.Y)
}

func (v *binaryOpVector) getZ() *bf128.FieldElement {
	return (*bf128.FieldElement)(&v.Z)
}

type unaryOpVector struct {
	X jsonBF128Element `json:"x"`
	Z jsonBF128Element `json:"z"`
}

func (v *unaryOpVector) getX() *bf128.FieldElement {
	return (*bf128.FieldElement)(&v.X)
}

func (v *unaryOpVector) getZ() *bf128.FieldElement {
	return (*bf128.FieldElement)(&v.Z)
}

type testVectors struct {
	Mul []binaryOpVector `json:"mul"`
	Div []binaryOpVector `json:"div"`
	Inv []unaryOpVector  `json:"inv"`
	Add []binaryOpVector `json:"add"`
	Sub []binaryOpVector `json:"sub"`
	Neg []binaryOpVector `json:"neg"`
}

func testBinaryOp(t *testing.T, vectors []binaryOpVector, op func(*bf128.FieldElement, *bf128.FieldElement) *bf128.FieldElement) {
	t.Helper()

	t.Run(runtime.FuncForPC(reflect.ValueOf(op).Pointer()).Name(), func(t *testing.T) {
		t.Parallel()
		for _, v := range vectors {
			x := v.getX()
			y := v.getY()
			expectedZ := v.getZ()
			actualZ := op(x, y)
			require.True(t, expectedZ.Equal(actualZ))
		}
	})
}

func testBinaryTryOp(t *testing.T, vectors []binaryOpVector, op func(*bf128.FieldElement, *bf128.FieldElement) (*bf128.FieldElement, error)) {
	t.Helper()
	t.Run(runtime.FuncForPC(reflect.ValueOf(op).Pointer()).Name(), func(t *testing.T) {
		t.Parallel()
		for _, v := range vectors {
			x := v.getX()
			y := v.getY()
			expectedZ := v.getZ()
			actualZ, err := op(x, y)
			require.NoError(t, err)
			require.True(t, expectedZ.Equal(actualZ))
		}
	})
}

func testUnaryOp(t *testing.T, vectors []binaryOpVector, op func(*bf128.FieldElement) *bf128.FieldElement) {
	t.Helper()
	t.Run(runtime.FuncForPC(reflect.ValueOf(op).Pointer()).Name(), func(t *testing.T) {
		t.Parallel()
		for _, v := range vectors {
			x := v.getX()
			expectedZ := v.getZ()
			actualZ := op(x)
			require.True(t, expectedZ.Equal(actualZ))
		}
	})
}

func testUnaryTryOp(t *testing.T, vectors []unaryOpVector, op func(*bf128.FieldElement) (*bf128.FieldElement, error)) {
	t.Helper()
	t.Run(runtime.FuncForPC(reflect.ValueOf(op).Pointer()).Name(), func(t *testing.T) {
		t.Parallel()
		for _, v := range vectors {
			x := v.getX()
			expectedZ := v.getZ()
			actualZ, err := op(x)
			require.NoError(t, err)
			require.True(t, expectedZ.Equal(actualZ))
		}
	})
}
