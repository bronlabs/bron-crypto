package hashcommitment_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	crs = []byte("00000001")

	inputMessages = [][][]byte{
		{[]byte("This is a test Message")},
		{[]byte("two short msgs - 1"), []byte("two short msgs - 2")},
		{[]byte(`This input field is intentionally longer than the SHA256 block size and the largest
		rate of all SHA3 variants as defined in NIST FIPS PUB 202 (i.e. r = 1152 bits = 144 bytes for SHA3-224) 
		to cover cases where multiple blocks have to be processed.`)},
		{{0xFB, 0x1A, 0x18, 0x47, 0x39, 0x3C, 0x9F, 0x45, 0x5F, 0x29, 0x4C, 0x51, 0x42, 0x30, 0xA6, 0xB9}},
		{{}},
	}
)

func TestHappyPathCommitment(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, message := range inputMessages {
		t.Run(string(slices.Concat(message[:]...)), func(t *testing.T) {
			t.Parallel()

			scheme := hashcommitment.NewScheme(crs)

			commitment, witness, err := scheme.Commit(message, prng)
			require.NoError(t, err)
			require.NotNil(t, commitment)
			require.NotNil(t, witness)

			err = scheme.Verify(message, commitment, witness)
			require.NoError(t, err)

			if len(message[0]) > 0 {
				message[0][0]++
				t.Run("should fail if message invalid", func(t *testing.T) {
					t.Parallel()

					err := scheme.Verify(message, commitment, witness)
					require.Error(t, err)

				})
			}
		})
	}
}
