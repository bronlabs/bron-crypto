package expanders_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c"

	_ "embed"
)

//go:embed testvectors/xmd_sha256.json
var testVectorXmdSha256Json string

//go:embed testvectors/xmd_sha256_long_dst.json
var testVectorXmdSha256JsonLongDst string

//go:embed testvectors/xmd_sha512.json
var testVectorXmdSha512Json string

type testVector struct {
	Msg string `json:"msg"`
	//nolint:tagliatelle // silence dumb linters
	LenInBytes uint `json:"len_in_bytes"`
	//nolint:tagliatelle // silence dumb linters
	UniformBytes string `json:"uniform_bytes"`
}

type testVectors struct {
	Dst   string       `json:"dst"`
	K     uint         `json:"k"`
	Cases []testVector `json:"cases"`
}

func Test_ExpandMessageXMDSha256(t *testing.T) {
	t.Parallel()

	var testCases testVectors
	err := json.Unmarshal([]byte(testVectorXmdSha256Json), &testCases)
	require.NoError(t, err)

	dst := testCases.Dst
	hash := sha256.New
	messageExpander := h2c.NewXMDMessageExpander(hash)
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

func Test_ExpandMessageXMDSha256LongDST(t *testing.T) {
	t.Parallel()

	var testCases testVectors
	err := json.Unmarshal([]byte(testVectorXmdSha256JsonLongDst), &testCases)
	require.NoError(t, err)

	dst := testCases.Dst
	hash := sha256.New
	messageExpander := h2c.NewXMDMessageExpander(hash)
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

func Test_ExpandMessageXMDSha512(t *testing.T) {
	t.Parallel()

	var testCases testVectors
	err := json.Unmarshal([]byte(testVectorXmdSha512Json), &testCases)
	require.NoError(t, err)

	dst := testCases.Dst
	hash := sha512.New
	messageExpander := h2c.NewXMDMessageExpander(hash)
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
