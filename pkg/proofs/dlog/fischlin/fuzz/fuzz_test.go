package fuzz

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/fischlin"
)

var allCurves = []curves.Curve{k256.New(), p256.New(), edwards25519.New(), pallas.New()}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), []byte("sid"), int64(0), []byte("secret"))
	f.Fuzz(func(t *testing.T, curveIndex uint, sid []byte, randomSeed int64, secretBytes []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randomSeed))
		prover, err := fischlin.NewProver(curve.Generator(), sid[:], nil, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		secret, err := curve.Scalar().Hash(secretBytes)
		if err != nil {
			t.Skip()
		}
		proof, statement, err := prover.Prove(secret)
		require.NoError(t, err)

		err = fischlin.Verify(curve.Point().Generator(), statement, proof, sid[:])
		require.NoError(t, err)
	})
}
