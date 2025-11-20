package ct_test

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"

	_ "embed"
)

//go:embed testvectors/vectors.json
var testVectorsData string

type hexBytes []byte

func (e *hexBytes) UnmarshalJSON(bytes []byte) error {
	var repr string
	err := json.Unmarshal(bytes, &repr)
	if err != nil {
		return err
	}
	beBytes, err := hex.DecodeString(repr)
	if err != nil {
		return err
	}
	*e = hexBytes(beBytes)
	return nil
}

type binaryOpVector struct {
	X hexBytes `json:"x"`
	Y hexBytes `json:"y"`
	Z hexBytes `json:"z"`
}

type unaryOpVector struct {
	X hexBytes `json:"x"`
	Z hexBytes `json:"z"`
}

type testVectors struct {
	And []binaryOpVector `json:"and"`
	Or  []binaryOpVector `json:"or"`
	Not []unaryOpVector  `json:"not"`
}

func testBinaryOp(t *testing.T, vectors []binaryOpVector, op func(dst, x, y []byte) int) {
	t.Helper()

	t.Run(runtime.FuncForPC(reflect.ValueOf(op).Pointer()).Name(), func(t *testing.T) {
		t.Parallel()
		for _, v := range vectors {
			x := []byte(v.X)
			y := []byte(v.Y)
			expectedZ := []byte(v.Z)

			actualZ := make([]byte, len(expectedZ))
			op(actualZ, x, y)

			require.Equal(t, expectedZ, actualZ)
		}
	})
}

func testUnaryOp(t *testing.T, vectors []unaryOpVector, op func(dst, x []byte) int) {
	t.Helper()

	t.Run(runtime.FuncForPC(reflect.ValueOf(op).Pointer()).Name(), func(t *testing.T) {
		t.Parallel()
		for _, v := range vectors {
			x := []byte(v.X)
			expectedZ := []byte(v.Z)

			actualZ := make([]byte, len(expectedZ))
			op(actualZ, x)

			require.Equal(t, expectedZ, actualZ)
		}
	})
}

func TestVectors(t *testing.T) {
	t.Parallel()
	var vectors testVectors
	err := json.Unmarshal([]byte(testVectorsData), &vectors)
	require.NoError(t, err)

	testBinaryOp(t, vectors.And, ct.AndBytes[[]byte])
	testBinaryOp(t, vectors.Or, ct.OrBytes[[]byte])
	testUnaryOp(t, vectors.Not, ct.NotBytes[[]byte])
}
