package fischlin_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/fischlin"
)

func Test_MeasureConstantTime_prove(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	sid := internal.GetBigEndianBytesWithLowestBitsSet(32, 32)
	prover, err := fischlin.NewProver(curve.Generator(), sid[:], nil, crand.Reader)
	require.NoError(t, err)

	var secret curves.Scalar
	internal.RunMeasurement(500, "fischlin_prove", func(i int) {
		secret, err = curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
	}, func() {
		prover.Prove(secret)
	})
}

func Test_MeasureConstantTime_verify(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	sid := internal.GetBigEndianBytesWithLowestBitsSet(32, 32)
	prover, err := fischlin.NewProver(curve.Generator(), sid[:], nil, crand.Reader)
	require.NoError(t, err)

	var proof *fischlin.Proof
	var statement fischlin.Statement
	internal.RunMeasurement(500, "fischlin_verify", func(i int) {
		secret, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		proof, statement, err = prover.Prove(secret)
		require.NoError(t, err)
	}, func() {
		fischlin.Verify(curve.Generator(), statement, proof, sid[:])
	})
}
