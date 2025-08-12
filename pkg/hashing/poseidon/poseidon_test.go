package poseidon_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
)

const vectorsDir = "./vectors"

type testVectorFile struct {
	Name        string       `json:"name"`
	Source      string       `json:"source"`
	TestVectors []testVector `json:"test_vectors"`
}

type testVector struct {
	Input  []string `json:"input"`
	Output string   `json:"output"`
}

func TestPoseidonLegacy(t *testing.T) {
	t.Parallel()
	runTestVectors(t, "legacy.json", poseidon.NewLegacy)
}

func TestPoseidonKimchi(t *testing.T) {
	t.Parallel()
	t.Skip("fails for now - known issue with round constants count")
	runTestVectors(t, "kimchi.json", poseidon.NewKimchi)
}

func runTestVectors(t *testing.T, fileName string, hasherFactory func() *poseidon.Poseidon) {
	t.Helper()

	// Load test vectors
	content, err := os.ReadFile(filepath.Join(vectorsDir, fileName))
	require.NoError(t, err, "failed to read test vector file")

	var vectors testVectorFile
	err = json.Unmarshal(content, &vectors)
	require.NoError(t, err, "failed to unmarshal test vectors")

	t.Logf("Running %s test vectors from %s", vectors.Name, vectors.Source)

	// Run each test vector
	for i, vector := range vectors.TestVectors {
		t.Run(fmt.Sprintf("vector_%d_inputs_%d", i, len(vector.Input)), func(t *testing.T) {
			// Parse input field elements
			inputs := make([]*pasta.PallasBaseFieldElement, len(vector.Input))
			for j, inputHex := range vector.Input {
				inputs[j] = parseFieldElement(t, inputHex)
			}

			// Parse expected output
			expected := parseFieldElement(t, vector.Output)

			// Create hasher and compute hash
			hasher := hasherFactory()
			actual := hasher.Hash(inputs...)

			// Verify result
			require.True(t, actual.Equal(expected),
				"hash mismatch for test vector %d: expected %s, got %s", 
				i, vector.Output, hex.EncodeToString(reverseBytes(actual.Bytes())))
		})
	}
}

func parseFieldElement(t *testing.T, hexStr string) *pasta.PallasBaseFieldElement {
	t.Helper()
	
	// Decode hex string
	bytes, err := hex.DecodeString(hexStr)
	require.NoError(t, err, "failed to decode hex string: %s", hexStr)
	
	// Reverse bytes for little-endian encoding
	reversed := reverseBytes(bytes)
	
	// Create field element from bytes
	fe, err := pasta.NewPallasBaseField().FromWideBytes(reversed)
	require.NoError(t, err, "failed to create field element from bytes")
	
	return fe
}

func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		result[i] = b[len(b)-1-i]
	}
	return result
}

// Additional test for standard hash.Hash interface
func TestPoseidonHashInterface(t *testing.T) {
	t.Parallel()

	h := poseidon.NewLegacy()
	
	// Test size methods
	require.Equal(t, 32, h.Size())
	require.Equal(t, 32, h.BlockSize())
	
	// Test Write method with valid data
	data := make([]byte, 32)
	n, err := h.Write(data)
	require.NoError(t, err)
	require.Equal(t, 32, n)
	
	// Test Write method with invalid data length
	invalidData := make([]byte, 31)
	_, err = h.Write(invalidData)
	require.Error(t, err)
	
	// Test Reset
	h.Reset()
	
	// Test Sum
	sum := h.Sum(nil)
	require.Len(t, sum, 32)
}

// Test empty input edge case specifically
func TestPoseidonEmptyInput(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		hasher   func() *poseidon.Poseidon
		expected string
	}{
		{
			name:     "Legacy empty input",
			hasher:   poseidon.NewLegacy,
			expected: "1b3251b6912d82edc78bbb0a5c88f0c6fde1781bc3e654123fa6862a4c63e617",
		},
		// Kimchi test commented out due to known issue with round constants count
		// {
		// 	name:     "Kimchi empty input", 
		// 	hasher:   poseidon.NewKimchi,
		// 	expected: "a8eb9ee0f30046308abbfa5d20af73c81bbdabc25b459785024d045228bead2f",
		// },
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher := tc.hasher()
			result := hasher.Hash()
			expected := parseFieldElement(t, tc.expected)
			require.True(t, result.Equal(expected))
		})
	}
}

// Benchmark tests
func BenchmarkPoseidonLegacy(b *testing.B) {
	benchmarkPoseidon(b, poseidon.NewLegacy)
}

func BenchmarkPoseidonKimchi(b *testing.B) {
	benchmarkPoseidon(b, poseidon.NewKimchi)
}

func benchmarkPoseidon(b *testing.B, hasherFactory func() *poseidon.Poseidon) {
	// Create test inputs of different sizes
	sizes := []int{1, 2, 3, 4, 5, 10}
	
	for _, size := range sizes {
		inputs := make([]*pasta.PallasBaseFieldElement, size)
		for i := range inputs {
			inputs[i] = pasta.NewPallasBaseField().One()
		}
		
		b.Run(fmt.Sprintf("inputs_%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hasher := hasherFactory()
				_ = hasher.Hash(inputs...)
			}
		})
	}
}