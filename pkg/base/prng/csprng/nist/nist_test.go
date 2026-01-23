/*
These tests are defined in the NIST SP 800-90A Deterministic Random Bit Generator
Validation System (DRBGVS) specification:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/DRBGVS.pdf
*/
package nist_test

import (
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng/nist"
	nist_testutils "github.com/bronlabs/bron-crypto/pkg/base/prng/csprng/nist/testutils"
	csprng_testutils "github.com/bronlabs/bron-crypto/pkg/base/prng/csprng/testutils"
)

// decode_or_panic decodes a hex string into a byte slice, or panics if the string is invalid.
func decodeHex_or_panic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Test_AES256_ApiUsage tests the PRNG API for the inputs defined in the last test case
// of "[AES-256 UseDF]" with PR false, COUNT=0, as part of the DRBGVS spec.
func Test_AES256_ApiUsage(t *testing.T) {
	t.Parallel()
	entropySource := io.Reader(nil) // Set to nil to force crypto/pcg.NewRandomised() by default
	keySize := 32                   // 256 bits

	entropyInput := decodeHex_or_panic("e2f75cf553035b3cb4d21e567ca5c203623d4a4b5885326f63ea61a020a4984e")
	nonce := decodeHex_or_panic("a666ee4b26dae5897fc5e85c643fc630")
	personalization := decodeHex_or_panic("19275bbd7a0109d8179334c55337bc0a3f5ac48cb8c4959c888c0b65f7ac9a84")
	entropyInputReseed := decodeHex_or_panic("f6672d022226b05db5d3c59c0da5b20a1be05ecabbd1744483ca4ce5571d93f4")
	additionalInputReseed := decodeHex_or_panic("8c8f940af45aec864c8aa8be60b100f82bb9670c7e2a392a4ab6f4b20eefbbaa")
	additionalInput1 := decodeHex_or_panic("26b5f0dadc891e0b1b78878e7ae75aee843376c0968c54c12759c18def21d363")
	additionalInput2 := decodeHex_or_panic("ff6791f4d4b29996b0399d95a14a28b8e2e20787531d916e7ed2ec040bbd7c84")
	expectedReturnedBits := decodeHex_or_panic("eb8f289bb05be84084840c3d2c9deea0245487a98d7e1a4017b860e48635213d622a4a4eae91efdd5342ade94093f199c16deb1e58d0088b9b4a0f24a5d15775")

	outputBuffer := make([]byte, len(expectedReturnedBits))
	// Initialise (instantiate) the PRNG
	prng, err := nist.NewNistPRNG(keySize, entropySource, entropyInput, nonce, personalization)
	require.NoError(t, err)
	// Reseed
	err = prng.Reseed(entropyInputReseed, additionalInputReseed)
	require.NoError(t, err)
	// Generate #1
	err = prng.Generate(outputBuffer, additionalInput1)
	require.NoError(t, err)
	// Generate #2
	prng.Generate(outputBuffer, additionalInput2)
	// Check the returned bits.
	require.Equal(t, expectedReturnedBits, outputBuffer)
	// Uninstantiate (destroy) the PRNG --> implicit (Garbage Collector)
}

// Test_AES128_ApiUsage tests the PRNG API for the inputs defined in the last test case
// of "[AES-128 UseDF]" with PR false, COUNT=0, as part of the DRBGVS spec.
func Test_AES128_ApiUsage(t *testing.T) {
	t.Parallel()
	entropySource := io.Reader(nil) // Use crypto/pcg.NewRandomised() by default
	keySize := 16                   // 128 bits

	entropyInput := decodeHex_or_panic("e796b728ec69cf79f97eaa2c06e7187f")
	nonce := decodeHex_or_panic("3568f011c282c01d")
	personalization := decodeHex_or_panic("b5ae693192ff057e682a629b84b8feec")
	entropyInputReseed := decodeHex_or_panic("31c4db5713e08e4e8cfbf777b9621a04")
	additionalInputReseed := decodeHex_or_panic("b6997617e4e2c94d8a3bf3c61439a55e")
	additionalInput1 := decodeHex_or_panic("c3998f9edd938286d7fad2cc75963fdd")
	additionalInput2 := decodeHex_or_panic("648fc7360ae27002e1aa77d85895b89e")
	expectedReturnedBits := decodeHex_or_panic("6ce1eb64fdca9fd3b3ef61913cc1c214f93bca0e515d0514fa488d8af529f49892bb7cd7fbf584eb020fd8cb2af9e6dbfce8a8a3439be85d5cc4de7640b4ef7d")

	outputBuffer := make([]byte, len(expectedReturnedBits))
	// Initialise (instantiate) the PRNG
	prng, err := nist.NewNistPRNG(keySize, entropySource, entropyInput, nonce, personalization)
	require.NoError(t, err)
	// Reseed
	err = prng.Reseed(entropyInputReseed, additionalInputReseed)
	require.NoError(t, err)
	// Generate #1
	prng.Generate(outputBuffer, additionalInput1)
	// Generate #2
	prng.Generate(outputBuffer, additionalInput2)
	// Check the returned bits.
	require.Equal(t, expectedReturnedBits, outputBuffer)
	// Uninstantiate (destroy) the PRNG --> implicit (Garbage Collector)
}

// Test_AES256_Read tests the PRNG Read for the inputs defined in the first test
// case of "[AES-256 UseDF]" no reseed, COUNT=0, as part of the DRBGVS spec.
func Test_AES256_ReadnResetState(t *testing.T) {
	t.Parallel()
	entropySource := io.Reader(nil) // Set to nil to force crypto/pcg.NewRandomised() by default
	keySize := 32                   // 256 bits

	entropyInput := decodeHex_or_panic("36401940fa8b1fba91a1661f211d78a0b9389a74e5bccfece8d766af1a6d3b14")
	nonce := decodeHex_or_panic("496f25b0f1301b4f501be30380a137eb")
	expectedReturnedBits := decodeHex_or_panic("5862eb38bd558dd978a696e6df164782ddd887e7e9a6c9f3f1fbafb78941b535a64912dfd224c6dc7454e5250b3d97165e16260c2faf1cc7735cb75fb4f07e1d")

	outputBuffer := make([]byte, len(expectedReturnedBits))
	// Initialise (instantiate) the PRNG
	prng, err := nist.NewNistPRNG(keySize, entropySource, entropyInput, nonce, nil)
	require.NoError(t, err)
	// Read #1
	prng.Read(outputBuffer)
	// Read #2
	prng.Read(outputBuffer)
	// Check the returned bits.
	require.Equal(t, expectedReturnedBits, outputBuffer)
	// Do it all over again, resetting the prng
	prng.Seed(entropyInput, nonce)
	prng.Read(outputBuffer)
	prng.Read(outputBuffer)
	require.Equal(t, expectedReturnedBits, outputBuffer)
}

func Test_NistPrng(t *testing.T) {
	t.Parallel()
	for _, keySize := range []int{16, 32} {
		prngGenerator := func(seed, salt []byte) (csprng.SeedableCSPRNG, error) {
			return nist.NewNistPRNG(keySize, nil, seed, salt, nil)
		}
		csprng_testutils.PrngTester(t, 32, 32, prngGenerator)
	}
}

func Test_NistValidation(t *testing.T) {
	t.Parallel()
	for _, testParams := range []struct {
		keySize int
		useDf   bool
	}{
		{keySize: 32, useDf: true}, // AES-256
		{keySize: 16, useDf: true}, // AES-128
	} {
		t.Run(
			fmt.Sprintf("PRNG[AES-%d UseDF=%t]", testParams.keySize, testParams.useDf),
			func(t *testing.T) {
				t.Parallel()
				require.NoError(t, nist_testutils.RunNistValidationTest(testParams.keySize, testParams.useDf))
			})
	}
}
