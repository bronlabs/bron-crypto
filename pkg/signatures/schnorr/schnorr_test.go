package schnorr_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	message := []byte("something")
	curveInstances := []curves.Curve{
		k256.New(),
		p256.New(),
		edwards25519.New(),
	}
	hs := []func() hash.Hash{
		sha3.New256,
		sha512.New,
	}
	for _, curve := range curveInstances {
		for i, h := range hs {
			boundedCurve := curve
			boundedH := h
			t.Run(fmt.Sprintf("running the test for curve %s and hash no %d", boundedCurve.Name(), i), func(t *testing.T) {
				t.Parallel()
				cipherSuite := &integration.CipherSuite{
					Curve: boundedCurve,
					Hash:  boundedH,
				}
				signer, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader)
				require.NoError(t, err)
				require.NotNil(t, signer)
				require.NotNil(t, signer.PublicKey)

				signature, err := signer.Sign(message)
				require.NoError(t, err)

				err = schnorr.Verify(cipherSuite, signer.PublicKey, message, signature)
				require.NoError(t, err)
			})
		}
	}
}

func Test_CanJsonMarshalAndUnmarshal(t *testing.T) {
	t.Parallel()
	message := []byte("something")
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha512.New,
	}
	signer, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.PublicKey)

	signature, err := signer.Sign(message)
	require.NoError(t, err)

	marshalled, err := json.Marshal(signature)
	require.NoError(t, err)
	require.Greater(t, len(marshalled), 0)

	var unmarshaled *schnorr.Signature
	err = json.Unmarshal(marshalled, &unmarshaled)
	require.NoError(t, err)
	require.Equal(t, signature, unmarshaled)
}
