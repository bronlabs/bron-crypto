package bls12381_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	itu "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
)

type pointG2 struct {
	Input struct {
		Point itu.HexBytes `json:"signature"`
	} `json:"input"`
	Output bool `json:"output"`
}

type hashedPointG2 struct {
	Input struct {
		Message string `json:"msg"`
	} `json:"input"`
	Output struct {
		X itu.HexBytesArray `json:"x"`
		Y itu.HexBytesArray `json:"y"`
	} `json:"output"`
}

// these test vectors are from the eth implementation
func TestHashToG2Vectors(t *testing.T) {
	t.Parallel()
	hashedDir := filepath.Join(dir, "hash_to_G2")

	files, err := os.ReadDir(hashedDir)
	require.NoError(t, err)

	curve := bls12381.NewG2()
	curve.SetHasherAppTag("QUUX-V01-CS02-with-")

	for _, file := range files[:1] {
		ff := file
		content, err := os.ReadFile(filepath.Join(hashedDir, ff.Name()))
		require.NoError(t, err)

		t.Run(ff.Name(), func(t *testing.T) {
			t.Parallel()
			var vector *hashedPointG2
			err := json.Unmarshal(content, &vector)
			require.NoError(t, err)

			require.NotNil(t, vector)
			require.NotNil(t, vector.Input)
			require.NotNil(t, vector.Output)
			require.NotNil(t, vector.Output.X)
			require.Len(t, vector.Output.X, 2)
			require.NotNil(t, vector.Output.Y)
			require.Len(t, vector.Output.Y, 2)

			actual, err := curve.Hash([]byte(vector.Input.Message))
			require.NoError(t, err)
			// https://github.com/ethereum/bls12-381-tests/blob/2b6a5ba046f2878da6e8a7b99ee3e457573a15cb/main.py#L646
			assert.EqualValues(t, vector.Output.X[0], actual.AffineX().SubFieldElement(0).Bytes(), "X coordinate.R")
			require.EqualValues(t, vector.Output.X[1], actual.AffineX().SubFieldElement(1).Bytes(), "X coordinate.I")
			require.EqualValues(t, vector.Output.Y[0], actual.AffineY().SubFieldElement(0).Bytes(), "Y coordinate.R")
			require.EqualValues(t, vector.Output.Y[1], actual.AffineY().SubFieldElement(1).Bytes(), "Y coordinate.I")
		})
	}
}

func testDeserializationG2(t *testing.T, vector *pointG2) {
	t.Helper()

	x, err := bls12381.NewG2().Point().FromAffineCompressed(vector.Input.Point)
	if vector.Output {
		require.NoError(t, err)
	} else {
		if x != nil && x.IsIdentity() {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}

// these test vectors are from the eth implementation
func TestDeserializationTestVectorsG2(t *testing.T) {
	t.Parallel()
	signDir := filepath.Join(dir, "deserialization_G2")

	files, err := os.ReadDir(signDir)
	require.NoError(t, err)

	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(signDir, file.Name()))
		require.NoError(t, err)

		var vector *pointG2
		json.Unmarshal(content, &vector)

		require.NotNil(t, vector)
		require.NotNil(t, vector.Input)

		t.Run(file.Name(), func(t *testing.T) {
			t.Parallel()
			testDeserializationG2(t, vector)
		})
	}
}
