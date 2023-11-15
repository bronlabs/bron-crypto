package schnorr

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
)

func Test_MeasureConstantTime_prove(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.New()
	sid := internal.GetBigEndianBytesWithLowestBitsSet(32, 32)
	var err error
	var secret curves.Scalar
	var prover *Prover

	internal.RunMeasurement(500, "schnorr_prove", func(i int) {
		secret, err = curve.Scalar().Random(crand.Reader)
		require.NoError(t, err)
		prover, err = NewProver(curve.Generator(), sid[:], nil)
		require.NoError(t, err)
	}, func() {
		prover.Prove(secret, crand.Reader)
	})
}

func Test_MeasureConstantTime_verify(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.New()
	sid := internal.GetBigEndianBytesWithLowestBitsSet(32, 32)
	var err error
	var secret curves.Scalar
	var prover *Prover
	var proof *Proof
	var statement Statement
	internal.RunMeasurement(500, "schnorr_verify", func(i int) {
		secret, err = curve.Scalar().Random(crand.Reader)
		require.NoError(t, err)
		prover, err = NewProver(curve.Generator(), sid[:], nil)
		require.NoError(t, err)
		proof, statement, err = prover.Prove(secret, crand.Reader)
		require.NoError(t, err)
	}, func() {
		Verify(curve.Generator(), statement, proof, sid[:], nil)
	})
}
