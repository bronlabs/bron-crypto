package schnorr

import (
	"crypto/rand"
	"fmt"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
)

func TestZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()
	uniqueSessionId := sha3.Sum256([]byte("random seed"))
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
		curves.ED25519(),
	}
	for _, curve := range curveInstances {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name), func(t *testing.T) {
			t.Parallel()
			prover, err := NewProver(boundedCurve.Point.Generator(), uniqueSessionId[:], nil)
			require.NoError(t, err)
			require.NotNil(t, prover)
			require.NotNil(t, prover.BasePoint)

			secret := boundedCurve.Scalar.Random(rand.Reader)
			statement := prover.BasePoint.Mul(secret)
			proof, err := prover.Prove(secret)
			require.NoError(t, err)

			err = Verify(boundedCurve.Point.Generator(), statement, proof, uniqueSessionId[:], nil)
			require.NoError(t, err)
		})
	}
}
func TestNotVerifyZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()
	uniqueSessionId := sha3.Sum256([]byte("random seed"))
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
		curves.ED25519(),
	}
	for _, curve := range curveInstances {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name), func(t *testing.T) {
			t.Parallel()
			prover, err := NewProver(boundedCurve.Point.Generator(), uniqueSessionId[:], nil)
			require.NoError(t, err)
			require.NotNil(t, prover)
			require.NotNil(t, prover.BasePoint)

			secret := boundedCurve.Scalar.Random(rand.Reader)
			proof, err := prover.Prove(secret)
			statement := boundedCurve.Scalar.Random(rand.Reader).Point()
			require.NoError(t, err)

			err = Verify(boundedCurve.Point.Generator(), statement, proof, uniqueSessionId[:], nil)
			require.True(t, errs.IsVerificationFailed(err))
		})
	}
}
