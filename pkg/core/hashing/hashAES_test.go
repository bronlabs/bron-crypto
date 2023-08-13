package hashing_test

import (
	"bytes"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/stretchr/testify/require"
)

// TODO: run PRNG statistical tests on the output of this hash.
func TestHashAes(t *testing.T) {
	// Hardcode multiple input data strings to hash, of sizes %BlockSize == 0.
	testInputs := []string{
		"0123456789ABCDEF0123456789ABCDEF",
		"He who controls the spice controls the universe.",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
	}
	testOutputLengths := []int{1, 2, 4}
	// Hardcode the expected outputs for the test inputs.
	expectedDigests := []string{
		"\x1c\xa2\xbcX\xa256\xde8K[O\xf1\x1eP\xc6",
		"/~N\xccφ\x9b\x7fY\n\x93\x82\xff5\xad\xd6Y}Q\xb7\xe3>\x8c\xbe\xaa\x91\xadR\x95\xa0\xee?",
		"}Z\xbf!\x7f\xe7k\xee\x19]\xee\xcbH\x90\xa47S@\xd6N\xc0\xf1\xb0\xe7\xfcj\x7f$~שwKSf\x9a\x03\x9b\xb6\xb1\x83o\x9ap\x90\x18\x1e\x16:\x83\xea(\xb8ص\xda\xe4h\x1c\x93\x8cF\xb2\x86",
	}
	// Hash each input and compare the output with the expected output.
	sessionId := []byte("ThisIsOne32BytesSessionIdExample")
	for i, input := range testInputs {
		inputBytes := []byte(input)
		iv := sessionId
		hash, err := hashing.NewHashAes(iv, testOutputLengths[i])
		require.NoError(t, err)
		n, err := hash.Write(inputBytes)
		require.NoError(t, err)
		require.Equal(t, n, hash.Size())
		digest := hash.Sum(nil)
		require.True(t, bytes.Equal(digest, []byte(expectedDigests[i])))
	}
}
