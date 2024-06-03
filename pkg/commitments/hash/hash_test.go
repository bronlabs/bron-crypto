package hashcommitments_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
)

var (
	sessionId = []byte("00000001")

	inputMessages = [][]byte{
		[]byte("This is a test Message"),
		[]byte("short msg"),
		[]byte(`This input field is intentionally longer than the SHA256 block size and the largest
		rate of all SHA3 variants as defined in NIST FIPS PUB 202 (i.e. r = 1152 bits = 144 bytes for SHA3-224) 
		to cover cases where multiple blocks have to be processed.`),
		{0xFB, 0x1A, 0x18, 0x47, 0x39, 0x3C, 0x9F, 0x45, 0x5F, 0x29, 0x4C, 0x51, 0x42, 0x30, 0xA6, 0xB9},
		{},
	}
)

func TestHappyPathCommitment(t *testing.T) {
	t.Parallel()

	prng := crand.Reader

	for _, message := range inputMessages {
		t.Run(string(message[:]), func(t *testing.T) {
			t.Parallel()

			committer, err := hashcommitments.NewCommitter(sessionId, prng)
			require.NoError(t, err)
			require.NotNil(t, committer)

			verifier := hashcommitments.NewVerifier(sessionId)
			require.NoError(t, err)
			require.NotNil(t, verifier)

			commit, opening, err := committer.Commit(message)
			require.NoError(t, err)
			require.NotNil(t, commit)
			require.NotNil(t, opening)

			err = verifier.Verify(commit, opening)
			require.NoError(t, err)
		})
	}
}
