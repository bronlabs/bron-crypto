package schnorr

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
)

func TestZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()
	uniqueSessionId := sha3.Sum256([]byte("random seed"))
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
				prover, err := NewProver(cipherSuite, nil, uniqueSessionId[:], nil)
				require.NoError(t, err)
				require.NotNil(t, prover)
				require.NotNil(t, prover.BasePoint)
				require.True(t, cipherSuite.Curve.Point.Generator().Equal(prover.BasePoint))

				secret := cipherSuite.Curve.Scalar.Random(rand.Reader)
				proof, err := prover.Prove(secret)
				require.NoError(t, err)

				err = Verify(cipherSuite, proof, nil, uniqueSessionId[:], nil)
				require.NoError(t, err)
			})
		}
	}
}
