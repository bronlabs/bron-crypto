package serialisation_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation/utils"
)

type TestObject struct {
	P                curves.Point
	Ps               []curves.Point
	S                curves.Scalar
	Ss               []curves.Scalar
	Value            string
	ArrayValue       []string
	NestedTestObject *NestedTestObject
	NestedPoint      *TestObject
	NilField         *NestedTestObject
}

type NestedTestObject struct {
	Value string
}

func TestPointMarshalling(t *testing.T) {
	testObj := TestObject{
		P:     k256.New().Point().Identity(),
		S:     k256.New().Scalar().Zero(),
		Value: "test",
	}
	testJson, err := json.Marshal(testObj)
	require.Equal(t, string(testJson), "{\"P\":{\"type\":\"secp256k1\",\"value\":\"020000000000000000000000000000000000000000000000000000000000000000\"},\"Ps\":null,\"S\":{\"type\":\"secp256k1\",\"value\":\"0000000000000000000000000000000000000000000000000000000000000000\"},\"Ss\":null,\"Value\":\"test\",\"ArrayValue\":null,\"NestedTestObject\":null,\"NestedPoint\":null,\"NilField\":null}")
	require.NoError(t, err)
}

func TestPointUnmarshalling(t *testing.T) {
	var testObj TestObject
	err := utils.UnmarshalCurveJSON([]byte(`{"P":{"type":"secp256k1","value":"020000000000000000000000000000000000000000000000000000000000000000"},"Ps":[{"type":"secp256k1","value":"020000000000000000000000000000000000000000000000000000000000000000"}],"S":{"type":"secp256k1","value":"0000000000000000000000000000000000000000000000000000000000000000"},"Ss":[{"type":"secp256k1","value":"0000000000000000000000000000000000000000000000000000000000000000"}],"Value":"test","ArrayValue":["a","b"],"NestedTestObject":{"Value":"n"},"NestedPoint":{"P":{"type":"secp256k1","value":"020000000000000000000000000000000000000000000000000000000000000000"}}}`), &testObj)
	require.NoError(t, err)
	require.NotNil(t, testObj.P)
	require.True(t, testObj.P.IsIdentity())
	require.Equal(t, 1, len(testObj.Ps))
	require.NotNil(t, testObj.S)
	require.True(t, testObj.S.IsZero())
	require.Equal(t, 1, len(testObj.Ss))
	require.Equal(t, "test", testObj.Value)
	require.Equal(t, "a", testObj.ArrayValue[0])
	require.Equal(t, "b", testObj.ArrayValue[1])
	require.Equal(t, "n", testObj.NestedTestObject.Value)
	require.NotNil(t, testObj.NestedPoint)
	require.True(t, testObj.NestedPoint.P.IsIdentity())
}
