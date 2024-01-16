package fuzz

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve()}

func Fuzz_Test(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, sid []byte, secretBytes []byte, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randomSeed))
		prover, err := schnorr.NewProver(curve.Generator(), sid[:], nil)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		require.NotNil(t, prover)
		require.NotNil(t, prover.BasePoint)

		secret, err := curve.Scalar().SetBytes(secretBytes)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		proof, statement, err := prover.Prove(secret, prng)
		require.NoError(t, err)

		err = schnorr.Verify(curve.Generator(), statement, proof, sid[:], nil)
		require.NoError(t, err)
	})
}
