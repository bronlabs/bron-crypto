package feldman_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
)

func Test_MeasureConstantTime_split(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	scheme, err := feldman.NewDealer(3, 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	var prover compiler.NIProver[batch_schnorr.Statement, batch_schnorr.Witness]
	protocol, err := batch_schnorr.NewSigmaProtocol(curve.Generator(), crand.Reader)
	require.NoError(t, err)
	comp, err := randomisedFischlin.NewCompiler(protocol, crand.Reader)
	require.NoError(t, err)
	internal.RunMeasurement(32*8, "feldman_split", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
		prover, err = comp.NewProver([]byte("test"), nil)
		require.NoError(t, err)
	}, func() {
		scheme.Split(secret, prover, crand.Reader)
	})
}

func Test_MeasureConstantTime_verify(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	scheme, err := feldman.NewDealer(3, 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	var commitments []curves.Point
	var shares []*feldman.Share
	var proof any
	var verifier compiler.NIVerifier[batch_schnorr.Statement]
	protocol, err := batch_schnorr.NewSigmaProtocol(curve.Generator(), crand.Reader)
	require.NoError(t, err)
	comp, err := randomisedFischlin.NewCompiler(protocol, crand.Reader)
	require.NoError(t, err)
	internal.RunMeasurement(32*8, "feldman_verify", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
		prover, err := comp.NewProver([]byte("test"), nil)
		require.NoError(t, err)
		verifier, err = comp.NewVerifier([]byte("test"), nil)
		require.NoError(t, err)
		commitments, shares, proof, err = scheme.Split(secret, prover, crand.Reader)
		require.NoError(t, err)
	}, func() {
		feldman.Verify(shares[0], commitments, verifier, proof)
	})
}

func Test_MeasureConstantTime_combine(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	scheme, err := feldman.NewDealer(3, 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	var shares []*feldman.Share
	protocol, err := batch_schnorr.NewSigmaProtocol(curve.Generator(), crand.Reader)
	require.NoError(t, err)
	comp, err := randomisedFischlin.NewCompiler(protocol, crand.Reader)
	require.NoError(t, err)
	internal.RunMeasurement(32*8, "feldman_combine", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
		prover, err := comp.NewProver([]byte("test"), nil)
		require.NoError(t, err)
		_, shares, _, err = scheme.Split(secret, prover, crand.Reader)
		require.NoError(t, err)
	}, func() {
		scheme.Combine(shares[0], shares[0], shares[1])
	})
}
