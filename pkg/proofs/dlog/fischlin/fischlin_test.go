package fischlin_test

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/proofs/dlog/fischlin"
)

func doFischlin(curve curves.Curve, sid []byte, prng io.Reader) error {
	prover, err := fischlin.NewProver(curve.Generator(), sid[:], nil, prng)
	if err != nil {
		return err
	}
	secret := curve.Scalar().Random(crand.Reader)
	proof, statement, err := prover.Prove(secret)
	if err != nil {
		return err
	}

	err = fischlin.Verify(curve.Point().Generator(), statement, proof, sid[:])
	if err != nil {
		return err
	}
	return nil
}

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
			if testing.Short() && boundedCurve.Name() != k256.Name {
				t.Skip("only running the K256 curve in short mode")
			}
			err := doFischlin(boundedCurve, uniqueSessionId[:], crand.Reader)
			require.NoError(t, err)
		})
	}
}

func TestNotVerifyZKPOverMultipleCurves(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip()
	}

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
			prover, err := fischlin.NewProver(boundedCurve.Point().Generator(), uniqueSessionId[:], nil, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, prover)
			require.NotNil(t, prover.BasePoint)

			secret := boundedCurve.Scalar().Random(crand.Reader)
			proof, _, err := prover.Prove(secret)
			badStatement := boundedCurve.Point().Random(crand.Reader)
			require.NoError(t, err)

			err = fischlin.Verify(boundedCurve.Point().Generator(), badStatement, proof, uniqueSessionId[:])
			require.True(t, errs.IsVerificationFailed(err))
		})
	}
}
