package schnorr

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

func TestZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()
	uniqueSessionId := sha3.Sum256([]byte("random seed"))
	curveInstances := []curves.Curve{
		k256.New(),
		p256.New(),
		edwards25519.New(),
	}
	for _, curve := range curveInstances {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			prover, err := NewProver(boundedCurve.Point().Generator(), uniqueSessionId[:], nil)
			require.NoError(t, err)
			require.NotNil(t, prover)
			require.NotNil(t, prover.BasePoint)

			secret := boundedCurve.Scalar().Random(crand.Reader)
			proof, statement, err := prover.Prove(secret)
			require.NoError(t, err)

			err = Verify(boundedCurve.Point().Generator(), statement, proof, uniqueSessionId[:], nil)
			require.NoError(t, err)
		})
	}
}

func TestNotVerifyZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()
	uniqueSessionId := sha3.Sum256([]byte("random seed"))
	curveInstances := []curves.Curve{
		k256.New(),
		p256.New(),
		edwards25519.New(),
	}
	for _, curve := range curveInstances {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			prover, err := NewProver(boundedCurve.Point().Generator(), uniqueSessionId[:], nil)
			require.NoError(t, err)
			require.NotNil(t, prover)
			require.NotNil(t, prover.BasePoint)

			secret := boundedCurve.Scalar().Random(crand.Reader)
			proof, _, err := prover.Prove(secret)
			badStatement := boundedCurve.Point().Random(crand.Reader)
			require.NoError(t, err)

			err = Verify(boundedCurve.Point().Generator(), badStatement, proof, uniqueSessionId[:], nil)
			require.True(t, errs.IsVerificationFailed(err))
		})
	}
}
