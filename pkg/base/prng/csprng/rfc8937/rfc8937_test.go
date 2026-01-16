//nolint:testpackage // Allow testing of unexported functions
package rfc8937

import (
	"crypto"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func TestUniqueOutputs(t *testing.T) {
	t.Parallel()
	suite, err := ecdsa.NewDeterministicSuite(p256.NewCurve(), crypto.SHA256)
	require.NoError(t, err)
	scheme, err := ecdsa.NewScheme(suite, nil)
	require.NoError(t, err)
	keygen, err := scheme.Keygen()
	require.NoError(t, err)
	sk, _, err := keygen.Generate(crand.Reader)
	require.NoError(t, err)
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)

	for _, n := range []int{5, 10, 256, 300} {
		for _, trialCount := range []int{10} {
			boundedN := n
			boundedTrialCount := trialCount
			t.Run(fmt.Sprintf("checkign uniqueness of %d samples of size [%d]byte", boundedTrialCount, boundedN), func(t *testing.T) {
				t.Parallel()

				wr, err := Wrap(crand.Reader, signer, []byte("unique-key-id"))
				require.NoError(t, err)

				seen := map[string]bool{}
				for range boundedTrialCount {
					output := make([]byte, boundedN)
					readN, err := wr.Read(output)
					require.NoError(t, err)
					require.Equal(t, boundedN, readN)

					encodedOutput := hex.EncodeToString(output)
					_, exists := seen[encodedOutput]
					require.False(t, exists)
					seen[encodedOutput] = true
				}

			})
		}
	}
}
