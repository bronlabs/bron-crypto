package expanders_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"

	_ "embed"
)

//go:embed testvectors/xof_shake128.json
var testVectorXofShake128Json string

//go:embed testvectors/xof_shake128_long_dst.json
var testVectorXofShake128LongDstJson string

//go:embed testvectors/xof_shake256.json
var testVectorXofShake256Json string

func Test_ExpandMessageXOFShake128(t *testing.T) {
	t.Parallel()

	var testCases testVectors
	err := json.Unmarshal([]byte(testVectorXofShake128Json), &testCases)
	require.NoError(t, err)

	dst := testCases.Dst
	hash := sha3.NewShake128()
	messageExpander := h2c.NewXOFMessageExpander(hash, testCases.K)
	for _, vector := range testCases.Cases {
		t.Run(fmt.Sprintf("%d:%s", vector.LenInBytes, vector.Msg), func(t *testing.T) {
			t.Parallel()

			expectedUniformBytes, err := hex.DecodeString(vector.UniformBytes)
			require.NoError(t, err)
			uniformBytes := messageExpander.ExpandMessage([]byte(dst), []byte(vector.Msg), vector.LenInBytes)
			require.Equal(t, expectedUniformBytes, uniformBytes)
		})
	}
}

func Test_ExpandMessageXOFShake128LongDST(t *testing.T) {
	t.Parallel()

	var testCases testVectors
	err := json.Unmarshal([]byte(testVectorXofShake128LongDstJson), &testCases)
	require.NoError(t, err)

	dst := testCases.Dst
	hash := sha3.NewShake128()
	messageExpander := h2c.NewXOFMessageExpander(hash, testCases.K)
	for _, vector := range testCases.Cases {
		t.Run(fmt.Sprintf("%d:%s", vector.LenInBytes, vector.Msg), func(t *testing.T) {
			t.Parallel()

			expectedUniformBytes, err := hex.DecodeString(vector.UniformBytes)
			require.NoError(t, err)
			uniformBytes := messageExpander.ExpandMessage([]byte(dst), []byte(vector.Msg), vector.LenInBytes)
			require.Equal(t, expectedUniformBytes, uniformBytes)
		})
	}
}

func Test_ExpandMessageXOFShake256(t *testing.T) {
	t.Parallel()

	var testCases testVectors
	err := json.Unmarshal([]byte(testVectorXofShake256Json), &testCases)
	require.NoError(t, err)

	dst := testCases.Dst
	hash := sha3.NewShake256()
	messageExpander := h2c.NewXOFMessageExpander(hash, testCases.K)
	for _, vector := range testCases.Cases {
		t.Run(fmt.Sprintf("%d:%s", vector.LenInBytes, vector.Msg), func(t *testing.T) {
			t.Parallel()

			expectedUniformBytes, err := hex.DecodeString(vector.UniformBytes)
			require.NoError(t, err)
			uniformBytes := messageExpander.ExpandMessage([]byte(dst), []byte(vector.Msg), vector.LenInBytes)
			require.Equal(t, expectedUniformBytes, uniformBytes)
		})
	}
}
