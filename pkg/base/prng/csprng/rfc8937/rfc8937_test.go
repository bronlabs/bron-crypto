//nolint:testpackage // Allow testing of unexported functions
package rfc8937

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/stretchr/testify/require"
)

func TestUniqueOutputs(t *testing.T) {
	t.Parallel()
	suite, err := ecdsa.NewSuite(p256.NewCurve(), sha256.New)
	require.NoError(t, err)
	scheme, err := ecdsa.NewDeterministicScheme(suite)
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

				wr, err := NewWrappedReader(crand.Reader, signer, []byte("unique-key-id"))
				require.NoError(t, err)

				seen := map[string]bool{}
				for trial := 0; trial < boundedTrialCount; trial++ {
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

func TestIncrementNonce(t *testing.T) {
	t.Parallel()
	suite, err := ecdsa.NewSuite(p256.NewCurve(), sha256.New)
	require.NoError(t, err)
	scheme, err := ecdsa.NewDeterministicScheme(suite)
	require.NoError(t, err)
	keygen, err := scheme.Keygen()
	require.NoError(t, err)
	sk, _, err := keygen.Generate(crand.Reader)
	require.NoError(t, err)
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)

	wr, err := NewWrappedReader(crand.Reader, signer, []byte("increment-nonce-key-id"))
	require.NoError(t, err)

	tag2Copy := wr.tag2

	wrWithExpectedTag2 := &WrappedReader{
		signer: wr.signer,
		prk:    wr.prk,
		tag2:   tag2Copy,
	}

	p := 3
	q := 1
	output := make([]byte, p*NBytes+q)
	incrementCount := p + q

	_, err = wr.Read(output)
	require.NoError(t, err)

	wrWithExpectedTag2.tag2 = wrWithExpectedTag2.tag2 + uint64(incrementCount)

	require.EqualValues(t, wrWithExpectedTag2.tag2, wr.tag2)

}
