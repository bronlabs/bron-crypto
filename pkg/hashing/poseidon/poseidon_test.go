package poseidon_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"

	_ "embed"
)

//go:embed vectors/legacy.json
var legacyVectors string

//go:embed vectors/kimchi.json
var kimchiVectors string

func TestPoseidonLegacy(t *testing.T) {
	t.Parallel()
	runTestVectors(t, legacyVectors, poseidon.NewLegacy)
}

func TestPoseidonKimchi(t *testing.T) {
	t.Parallel()
	runTestVectors(t, kimchiVectors, poseidon.NewKimchi)
}

// Additional test for standard hash.Hash interface
func TestPoseidonHashInterface(t *testing.T) {
	t.Parallel()

	h := poseidon.NewLegacy()

	// Test size methods
	require.Equal(t, 32, h.Size())
	require.Equal(t, 64, h.BlockSize())

	// Test Write method with valid data
	data := make([]byte, 64)
	n, err := h.Write(data)
	require.NoError(t, err)
	require.Equal(t, 64, n)

	// Test Write method with invalid data length
	invalidData := make([]byte, 65)
	_, err = h.Write(invalidData)
	require.Error(t, err)

	// Test Reset
	h.Reset()

	// Test Sum
	sum := h.Sum(nil)
	require.Len(t, sum, 32)

	t.Run("should accumulate", func(t *testing.T) {
		t.Parallel()

		prng := pcg.NewRandomised()
		x1, err := pasta.NewPallasBaseField().Random(prng)
		require.NoError(t, err)
		x2, err := pasta.NewPallasBaseField().Random(prng)
		require.NoError(t, err)
		x3, err := pasta.NewPallasBaseField().Random(prng)
		require.NoError(t, err)
		x4, err := pasta.NewPallasBaseField().Random(prng)
		require.NoError(t, err)

		h1 := hashing.HashFuncTypeErase(poseidon.NewLegacy)()
		h1.Write(slices.Concat(x1.Bytes(), x2.Bytes(), x3.Bytes(), x4.Bytes()))
		d1 := h1.Sum(nil)

		h2 := hashing.HashFuncTypeErase(poseidon.NewLegacy)()
		h2.Write(slices.Concat(x1.Bytes(), x2.Bytes()))
		h2.Write(slices.Concat(x3.Bytes(), x4.Bytes()))
		d2 := h2.Sum(nil)

		require.Equal(t, d1, d2)
	})

	t.Run("should preserve state", func(t *testing.T) {
		t.Parallel()

		prng := pcg.NewRandomised()
		x1, err := pasta.NewPallasBaseField().Random(prng)
		require.NoError(t, err)
		x2, err := pasta.NewPallasBaseField().Random(prng)
		require.NoError(t, err)

		p := poseidon.NewLegacy()
		err = p.Update(x1, x2)
		require.NoError(t, err)
		d1 := p.Digest()
		p.Sum([]byte("qwertyuiqwertyuiqwertyuiqwertyui"))
		d2 := p.Digest()

		require.Equal(t, d1, d2)
	})

	t.Run("should prepend prefix", func(t *testing.T) {
		t.Parallel()

		prng := pcg.NewRandomised()
		x1, err := pasta.NewPallasBaseField().Random(prng)
		require.NoError(t, err)
		x2, err := pasta.NewPallasBaseField().Random(prng)
		require.NoError(t, err)

		prefix := []byte("qwertyuiqwertyuiqwertyuiqwertyui")
		p := poseidon.NewLegacy()
		err = p.Update(x1, x2)
		require.NoError(t, err)
		d := p.Sum([]byte("qwertyuiqwertyuiqwertyuiqwertyui"))

		require.Equal(t, d[:32], prefix)

		sum := p.Sum(prefix)
		require.Len(t, sum, len(prefix)+32)
		require.Equal(t, prefix, sum[:len(prefix)])
		require.Equal(t, p.Digest().Bytes(), sum[len(prefix):])
	})
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
		{
			name:     "Kimchi empty input",
			hasher:   poseidon.NewKimchi,
			expected: "a8eb9ee0f30046308abbfa5d20af73c81bbdabc25b459785024d045228bead2f",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hasher := tc.hasher()
			result := hasher.Digest()
			expected := parseFieldElement(t, tc.expected)
			require.True(t, result.Equal(expected))

			err := hasher.Update()
			require.NoError(t, err)
			result = hasher.Digest()
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

type testVectorFile struct {
	Name        string       `json:"name"`
	Source      string       `json:"source"`
	TestVectors []testVector `json:"test_vectors"`
}

type testVector struct {
	Input  []string `json:"input"`
	Output string   `json:"output"`
}

func runTestVectors(t *testing.T, content string, hasherFactory func() *poseidon.Poseidon) {
	t.Helper()

	var vectors testVectorFile
	err := json.Unmarshal([]byte(content), &vectors)
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
			err := hasher.Update(padInput(inputs, hasher.Rate())...)
			require.NoError(t, err, "failed to update hasher")
			actual := hasher.Digest()

			// Verify result
			require.True(t, actual.Equal(expected),
				"hash mismatch for test vector %d: expected %s, got %s",
				i, vector.Output, hex.EncodeToString(reverseBytes(actual.Bytes())))
		})
	}
}

func benchmarkPoseidon(b *testing.B, hasherFactory func() *poseidon.Poseidon) {
	b.Helper()
	// Create test inputs of different sizes
	rate := hasherFactory().Rate()
	sizes := []int{rate * 1, rate * 2, rate * 3, rate * 4, rate * 5, rate * 10}

	for _, size := range sizes {
		inputs := make([]*pasta.PallasBaseFieldElement, size)
		for i := range inputs {
			inputs[i] = pasta.NewPallasBaseField().One()
		}

		b.Run(fmt.Sprintf("inputs_%d", size), func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				hasher := hasherFactory()
				_ = hasher.Update(inputs...)
				_ = hasher.Digest()
			}
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
	for i := range b {
		result[i] = b[len(b)-1-i]
	}
	return result
}

func padInput(input []*pasta.PallasBaseFieldElement, rate int) []*pasta.PallasBaseFieldElement {
	// pad with zeros
	for len(input)%rate != 0 {
		input = append(input, pasta.NewPallasBaseField().Zero())
	}
	return input
}
