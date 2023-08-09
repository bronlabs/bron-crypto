package fischlin_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/proofs/fischlin"
)

func TestZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()
	uniqueSessionId := sha3.Sum256([]byte("random seed"))
	curveInstances := []*curves.Curve{
		curves.K256(),
		// curves.P256(),
		// curves.ED25519(),
	}
	for _, curve := range curveInstances {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name), func(t *testing.T) {
			t.Parallel()
			prover, err := fischlin.NewProver(boundedCurve.Point.Generator(), uniqueSessionId[:], nil, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, prover)
			require.NotNil(t, prover.BasePoint)
			secret := boundedCurve.Scalar.Random(crand.Reader)
			proof, statement, err := prover.Prove(secret)
			require.NoError(t, err)

			err = fischlin.Verify(boundedCurve.Point.Generator(), statement, proof, uniqueSessionId[:])
			require.NoError(t, err)
		})
	}
}

// func TestNotVerifyZKPOverMultipleCurves(t *testing.T) {
// 	t.Parallel()
// 	uniqueSessionId := sha3.Sum256([]byte("random seed"))
// 	curveInstances := []*curves.Curve{
// 		curves.K256(),
// 		curves.P256(),
// 		curves.ED25519(),
// 	}
// 	for _, curve := range curveInstances {
// 		boundedCurve := curve
// 		t.Run(fmt.Sprintf("running the test for curve %s", boundedCurve.Name), func(t *testing.T) {
// 			t.Parallel()
// 			prover, err := fischlin.NewProver(boundedCurve.Point.Generator(), uniqueSessionId[:], nil, crand.Reader)
// 			require.NoError(t, err)
// 			require.NotNil(t, prover)
// 			require.NotNil(t, prover.BasePoint)

// 			secret := boundedCurve.Scalar.Random(crand.Reader)
// 			proof, _, err := prover.Prove(secret)
// 			badStatement := boundedCurve.Point.Random(crand.Reader)
// 			require.NoError(t, err)

// 			err = fischlin.Verify(boundedCurve.Point.Generator(), badStatement, proof, uniqueSessionId[:])
// 			require.True(t, errs.IsVerificationFailed(err))
// 		})
// 	}
// }
