package schnorr_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/schnorr"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	message := []byte("something")
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
		curves.ED25519(),
	}
	hs := []func() hash.Hash{
		sha3.New256,
		sha512.New,
	}
	for _, curve := range curveInstances {
		for i, h := range hs {
			boundedCurve := curve
			boundedH := h
			t.Run(fmt.Sprintf("running the test for curve %s and hash no %d", boundedCurve.Name, i), func(t *testing.T) {
				t.Parallel()
				cipherSuite := &integration.CipherSuite{
					Curve: boundedCurve,
					Hash:  boundedH,
				}
				signer, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader, nil)
				require.NoError(t, err)
				require.NotNil(t, signer)
				require.NotNil(t, signer.PublicKey)

				signature, err := signer.Sign(message)
				require.NoError(t, err)

				err = schnorr.Verify(cipherSuite, signer.PublicKey, message, signature, nil)
				require.NoError(t, err)
			})
		}
	}
}

func Test_CanJsonMarshalAndUnmarshal(t *testing.T) {
	t.Parallel()
	message := []byte("something")
	cipherSuite := &integration.CipherSuite{
		Curve: curves.K256(),
		Hash:  sha512.New,
	}
	signer, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader, nil)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.PublicKey)

	signature, err := signer.Sign(message)
	require.NoError(t, err)

	marshaled, err := json.Marshal(signature)
	require.NoError(t, err)
	require.Greater(t, len(marshaled), 0)

	var unmarshaled schnorr.Signature
	err = json.Unmarshal(marshaled, &unmarshaled)
	require.NoError(t, err)
	require.NotNil(t, unmarshaled.C)
	require.Equal(t, unmarshaled, signature)
}
